#include <iostream>
#include <span>
#include <core/pack_types.hpp>
#include <core/pack.hpp>
#include <core/common.hpp>
#include <btclibs/serialize.h>

#define DEBUG_TIME(F, res)   \
    {\
        c2pool::debug_timestamp _t;\
        (F);\
        c2pool::debug_timestamp _t2;\
        res += (_t2 - _t).t.count();\
    }


int main()
{
    c2pool::debug_timestamp begin;
    double t1 = 0, t2 = 0, t3 = 0;
    for (int i = 0; i < 1000000; i++)
    {
        IntType(64) t;
        DEBUG_TIME(t.set(123), t1);

        PackStream stream;
        // DEBUG_TIME(stream << t, t2);
        stream << t;

        IntType(64) t2;
        DEBUG_TIME(stream >> t2, t3);
    }
    c2pool::debug_timestamp final;

    std::cout << final - begin << std::endl;
    std::cout << "SET: " << t1 << std::endl;
    std::cout << "WRITE: " << t2 << std::endl;
    std::cout << "READ: " << t3 << std::endl;
}