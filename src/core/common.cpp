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

uint32_t timestamp()
{
    return std::time(nullptr);
}

} // namespace core