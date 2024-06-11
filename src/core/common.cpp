#include "common.hpp"

namespace c2pool
{

std::function<int()> count_generator()
{
    int i = 0;
    return [=]() mutable {
        i++;
        return i;
    };
}

}