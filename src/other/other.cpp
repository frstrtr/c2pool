#include <iostream>
#include <boost/random.hpp>
#include <vector>
#include <ctime>
#include <cmath>

namespace c2pool::random{
    using namespace boost::random;

    boost::random::mt19937 generator(std::time(0));

    ///[min, max)
    int RandomInt(int min, int max){
        boost::random::uniform_int_distribution<> rnd(min, max-1);
        return rnd(generator);
    }

    ///[min, max]
    float RandomFloat(float min, float max){
        float Min = float(min), Max = float(max);
        boost::random::uniform_int_distribution<> rnd(Min,Max);
        float res = ((float) rnd(generator) / Max);
        float range = Max - Min;
        res = (res*range) + Min;
        return res;
    }

    template <typename T>
    T RandomChoice(std::vector<T> list){
        int pos = RandomInt(0, list.size());
        return list[pos];
    }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l){

        return (log(RandomInt(1, RAND_MAX)+1)-log(RAND_MAX))/(-l);
    }

}

namespace c2pool::time{
    int timestamp(){
        return std::time(nullptr);
    }
}

namespace c2pool::str
{
    void substr(char *dest, char *source, int from, int length)
    {
        strncpy(dest, source + from, length);
        dest[length] = 0;
    }
} // namespace c2pool::str