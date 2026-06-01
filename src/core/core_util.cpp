#include <core/core_util.hpp>

#include <ctime>

namespace core
{

uint32_t timestamp()
{
    return std::time(nullptr);
}

} // namespace core
