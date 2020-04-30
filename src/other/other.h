#ifndef CPOOL_OTHER_H
#define CPOOL_OTHER_H

#include <vector>

namespace c2pool::random{
    ///[min, max)
    int RandomInt(int min, int max);

    ///[min, max]
    float RandomFloat(float min, float max);

    template <typename T>
    T RandomChoice(std::vector<T> list);

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l);
}

namespace c2pool::time{
    int timestamp();
}


#endif //CPOOL_OTHER_H

/*

#ifndef CPOOL_FACTORY_H
#define CPOOL_FACTORY_H
#endif //CPOOL_FACTORY_H

*/