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

template <typename HashType, int64_t Version>
struct BaseShare
{
    using hash_t = HashType;
    
    constexpr static int32_t version = Version;
    hash_t m_hash{};
    hash_t m_prev_hash{};

    constexpr static bool check_version(int threshold_version)
    {
        return version >= threshold_version;
    }

    BaseShare() {}
    BaseShare(const hash_t& hash, const hash_t& prev_hash) : m_hash(hash), m_prev_hash(prev_hash) {}
};

template <typename T>
concept is_share_type = std::is_base_of<BaseShare<typename T::hash_t, T::version>, T>::value;

template <typename Correct, typename...Ts>
concept is_correct_share = (std::is_same<Correct, Ts>::value || ...);

template <typename...Args>
struct ShareVariants : std::variant<Args*...>
{
    static_assert((is_share_type<Args> && ...), "ShareVariants parameters must inherit from BaseShare");

    // Use macros .call(<func>)
    template<typename F>
    void call_func(F&& func)
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

} // namespace chain

} // namespace c2pool

#define call(func) call_func([](auto& obj) { func (obj);})