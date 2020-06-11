#ifndef CPOOL_OTHER_H
#define CPOOL_OTHER_H

#include <vector>
#include <cstring>

namespace c2pool::random
{
    ///[min, max)
    int RandomInt(int min, int max);

    ///[min, max]
    float RandomFloat(float min, float max);

    template <typename T>
    T RandomChoice(std::vector<T> list);

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l);
} // namespace c2pool::random

namespace c2pool::time
{
    int timestamp();
}

namespace c2pool::str
{
    void substr(char *dest, char *source, int from, int length)
    {
        strncpy(dest, source + from, length);
        dest[length] = 0;
    }
} // namespace c2pool::str
#endif //CPOOL_OTHER_H