#include <iostream>
#include <core/pack_types.hpp>
#include <core/pack.hpp>
#include <btclibs/serialize.h>

int main()
{
    IntType(32) t;
    t.set(123);

    PackStream stream;
    stream << t;

    IntType(32) t2;
    stream >> t2;

    std::cout << t2.get() << std::endl;
}