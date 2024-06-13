#pragma once

#include <variant>
#include <type_traits>
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

    constexpr static bool check_version(int threshold_version)
    {
        return version >= threshold_version;
    }
};

template <typename T>
concept is_share_type = std::is_base_of<BaseShare<T::version>, T>::value;

template <typename Correct, typename...Ts>
concept is_correct_share = (std::is_same<Correct, Ts>::value || ...);

template <typename...Args>
struct ShareVariants : std::variant<Args*...>
{
    static_assert((is_share_type<Args> && ...), "ShareVariants parameters must inherit from BaseShare");

    // Use macros .INVOKE(<func>)
    template<typename F>
    void invoke(F&& func)
    {
        std::visit(func, *this);
    }

    template <typename T>
    ShareVariants& operator=(T* value)
    {
        static_assert((std::is_same_v<T, Args> || ...), "ShareVariants can be cast only to Args...");
        std::variant<Args*...>::operator = (value);
        return *this;
    }
};

#define INVOKE(func) invoke([](auto& obj) { func (obj);})

} // namespace chain

} // namespace c2pool