#include "common.hpp"
namespace core
{

uint32_t timestamp()
{
    return std::time(nullptr);
}

} // namespace core