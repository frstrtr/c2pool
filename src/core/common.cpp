#include "common.hpp"

namespace core
{

std::function<int()> count_generator()
{
    int i = 0;
    return [=]() mutable {
        i++;
        return i;
    };
}

} // namespace core