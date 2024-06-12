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

template <int64_t VERSION>
struct BaseShare
{
    constexpr static int32_t version = VERSION;
};

template <typename T>
concept is_share_type = std::is_base_of<BaseShare<T::version>, T>::value;

template <typename Correct, typename...Ts>
concept is_correct_share = (std::is_same<Correct, Ts>::value || ...);

template <typename...Args>
struct ShareVariants : std::variant<Args...>
{
    static_assert((is_share_type<Args> && ...), "ShareVariants parameters must inherit from BaseShare");

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