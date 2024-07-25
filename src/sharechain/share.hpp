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

// Formatter template:
// struct Formatter
// {
//     template <typename StreamType, typename ShareT>
//     static StreamType& pack_share(StreamType& os, ShareT* share)
//     {
//         return os;
//     }

//     template <typename StreamType, typename ShareT>
//     static StreamType& unpack_share(StreamType& is, ShareT* share)
//     {
//         return is;
//     }
// };

template <typename Formatter, typename...Args>
struct ShareVariants : std::variant<Args*...>
{
    static_assert((is_share_type<Args> && ...), "ShareVariants parameters must inherit from BaseShare");
    // static_assert((is_packstream_type<Args> && ...), "ShareVariant parameters must have implementations Serialize/Unserialize");

private:
    using load_map = std::map<int64_t, std::function<ShareVariants<Formatter, Args...>()>>;
    static load_map LoadMethods;

    static load_map init_load_map()
    {
        load_map some_map;
        ((some_map[Args::version] = []() { ShareVariants<Formatter, Args...> result; result = new Args(); return result; }), ...);
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

    // Use macros .call(<func>)
    template<typename F>
    auto invoke(F&& func)
    {
        return std::visit(func, *this);
    }

    template <typename T>
    ShareVariants& operator=(T* value)
    {
        static_assert((std::is_same_v<T, Args> || ...), "ShareVariants can be cast only to Args...");
        std::variant<Args*...>::operator = (value);
        return *this;
    }

    auto hash() const
    {
        return std::visit([&](auto* share){ return share->m_hash; }, *this);
    }

    auto prev_hash() const
    {
        return std::visit([&](auto* share){ return share->m_prev_hash; }, *this);
    }

    template <typename StreamType, typename Func>
    struct Wrapper
    {
        StreamType& m_stream;
        Func m_func;

        Wrapper(StreamType& stream, Func&& func) : m_stream(stream), m_func(func) { }

        template <typename ShareType>
        Wrapper operator()(ShareType* share)
        {
            m_func(m_stream, share);
            return *this;    
        }
    };

    template <typename StreamType>
    StreamType& pack(StreamType& os)
    {
        return invoke(Wrapper(os, [](auto& stream, auto* share) { Formatter::pack_share(stream, share); })).m_stream;
    }

    template <typename StreamType>
    StreamType& unpack(StreamType& is)
    {
        // StreamType* s = &is;
        return invoke(Wrapper(is, [](auto& stream, auto* share) { Formatter::unpack_share(stream, share); })).m_stream;
        // return is;
    }
};

template <typename Formatter, typename... Args>
typename ShareVariants<Formatter, Args...>::load_map ShareVariants<Formatter, Args...>::LoadMethods = ShareVariants<Formatter, Args...>::init_load_map();

} // namespace chain

// For actions, example: share.ACTION({...});
// obj -- parsed share; share_t -- share type
#define ACTION(action) invoke([&](auto obj) { using share_t = std::remove_pointer_t<decltype(obj)>; action })

// For func with arguments, example: share.CALL(func, a, b, c, d, ...);
#define CALL(func, ...) invoke([&](auto& obj) { func (obj, __VA_ARGS__); })

// For func without arguments, example: share.USE(func);
#define USE(func) invoke([&](auto& obj) { func (obj); })
