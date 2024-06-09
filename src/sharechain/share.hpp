#pragma once

#include <variant>
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

template <typename...Args>
struct ShareRefType : std::variant<Args...>
{
    // Use macros .INVOKE(<func>)
    template<typename F>
    void invoke(F&& func)
    {
        std::visit(func, *this);
    }

};

#define INVOKE(func) .invoke([](auto& obj) { ##func (obj);})


} // namespace chain

} // namespace c2pool