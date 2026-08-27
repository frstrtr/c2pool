// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <map>
#include <variant>
#include <functional>
#include <type_traits>
#include <core/pack.hpp>
#include <core/pack_types.hpp>

namespace chain
{

struct RawShare
{
    uint64_t type;
    BaseScript contents;

    RawShare() {}
    RawShare(uint64_t version, BaseScript script) : type(version), contents(script) { }
    RawShare(uint64_t version, PackStream stream) : type(version), contents(stream) { }

    C2POOL_SERIALIZE_METHODS(RawShare) { READWRITE(VarInt(obj.type), obj.contents); }
};

template <typename HashType, int64_t Version>
struct BaseShare
{
    using hash_t = HashType;
    
    constexpr static int64_t version = Version;
    hash_t m_hash{};
    hash_t m_prev_hash{};

    // Transient (NEVER serialized): PoW hash computed by share_init_verify()
    // when the share was received (phase 1 on the verify pool) or created
    // locally. Carries the PoW result WITH the share across threads —
    // the thread_local scratch (g_last_pow_hash / g_last_init_is_block) set
    // on a verify-pool worker is invisible to the compute thread that later
    // runs attempt_verify() with check_pow=false, which silently dropped
    // every peer-found block (parent-chain AND merged/aux) from the
    // found-blocks store. Null when PoW has not been computed for this
    // in-memory instance (e.g. shares loaded from LevelDB with a cached
    // index pow_hash).
    hash_t m_pow_hash{};

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
        share.Unserialize(is);

        return share;
    }

    // Use macros .call(<func>)
    template<typename F>
    auto invoke(F&& func)
    {
        return std::visit(func, *this);
    }

    template<typename F>
    auto invoke_const(F&& func) const
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

    /// Free the heap-allocated share object held by this variant.
    void destroy()
    {
        std::visit([](auto* ptr) { delete ptr; }, *this);
    }

    /// Deep-copy the held share into a NEW heap allocation the returned variant
    /// OWNS. Use when a BORROWED variant — one that aliases a raw pointer the
    /// sharechain owns and frees under its lock — must outlive that lock. The
    /// caller destroy()s the returned copy. Same borrow-vs-own discipline as the
    /// #1131/#1163 verified.remove(owns_data=false) fix: a borrowing view must
    /// never free, and a value that has to survive the lock must own its memory.
    ShareVariants clone() const
    {
        return std::visit([](auto* ptr) {
            using share_t = std::remove_const_t<std::remove_pointer_t<decltype(ptr)>>;
            ShareVariants copy;
            copy = new share_t(*ptr);
            return copy;
        }, *this);
    }

    auto version() const
    {
        return std::visit([&](auto* share){ return share->version; }, *this);
    }

    auto hash() const
    {
        return std::visit([&](auto* share){ return share->m_hash; }, *this);
    }

    auto prev_hash() const
    {
        return std::visit([&](auto* share){ return share->m_prev_hash; }, *this);
    }

    template <typename StreamType>
    StreamType& Serialize(StreamType& os) const
    {
        return invoke_const(chain::Wrapper(os, [](auto& stream, const auto* share) { Formatter::Write(stream, share); })).m_stream;
    }

    template <typename StreamType>
    StreamType& Unserialize(StreamType& is)
    {
        return invoke(chain::Wrapper(is, [](auto& stream, auto* share) { Formatter::Read(stream, share); })).m_stream;
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

#define SHARE_FORMATTER()\
    template<typename StreamType, typename ShareT>\
    static void Write(StreamType &stream, const ShareT* obj) { FormatAction<ShareT::version>(stream, obj, SerializeFormatter{}); }\
    template<typename StreamType, typename ShareT>\
    static void Read(StreamType &stream, ShareT* obj) { FormatAction<ShareT::version>(stream, obj, UnserializeFormatter{}); }\
    template<int64_t version, typename StreamType, typename ShareT, typename StreamFormatter>\
    static void FormatAction(StreamType &stream, ShareT* obj, StreamFormatter formatter)