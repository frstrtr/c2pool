#pragma once

#include <core/pack.hpp>

namespace c2pool
{

namespace chain
{

struct RawShare
{
    uint64_t type;
    PackStream contents;

    SERIALIZE_METHODS(RawShare) { READWRITE(obj.type, obj.contents); }
};
    

} // namespace chain

} // namespace c2pool