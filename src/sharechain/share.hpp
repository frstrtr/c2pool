#pragma once

#include <map>
#include <variant>
#include <functional>
#include <type_traits>
#include <core/pack.hpp>

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

private:
    using load_map = std::map<int64_t, std::function<ShareVariants<Args...>()>>;
    static load_map LoadMethods;

    static load_map init_load_map()
    {
        load_map some_map;
        ((some_map[Args::version] = []() { ShareVariants<Args...> result; result = new Args(); return result; }), ...);
        return some_map;
    }

public:
    template <typename StreamType>
    static ShareVariants load(int64_t version, StreamType& is)
    {
        if (!LoadMethods.contains(version))
            throw std::invalid_argument("ShareVariants::unpack -- version unsupported!");
        
        auto share = LoadMethods[version]();
        share.unpack(is);

        return share;
    }

    template <typename StreamType>
    PackStream& pack(StreamType& os)
    {
        call_func([&](auto* share) { ::Serialize(os, *share); });
        return os;
    }

    template <typename StreamType>
    PackStream& unpack(StreamType& is)
    {
        call_func([&](auto* share) { ::Unserialize(is, *share); });
        return is;
    }

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

template <typename... Args>
typename ShareVariants<Args...>::load_map ShareVariants<Args...>::LoadMethods = ShareVariants<Args...>::init_load_map();

} // namespace chain

#define CALL(func) call_func([](auto& obj) { func (obj);})