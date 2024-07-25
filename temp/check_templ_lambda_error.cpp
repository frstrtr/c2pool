#include <iostream>
#include <variant>
#include <map>
#include <functional>


struct PackStream
{
    int m_counter = 0;
    PackStream() {}
    PackStream(int counter) : m_counter(counter) { }
};

struct RawShare
{
    int type;
    PackStream contents;

    RawShare(int _type, PackStream _content) : type(_type), contents(_content) 
    {

    }
};

struct Formatter
{
    template <typename StreamType, typename ShareT>
    static StreamType& pack_share(StreamType& os, ShareT* share)
    {
        return os;
    }

    template <typename StreamType, typename ShareT>
    static StreamType& unpack_share(StreamType& is, ShareT* share)
    {
        return is;
    }
};

struct A
{
    static constexpr int version = 10;
};

struct B
{
    static constexpr int version = 20;
};

struct Share : public std::variant<A*>
{
    template<typename F>
    auto invoke(F&& func)
    {
        // return std::visit(Formatter::unpack_share, *this);
        return std::visit(func, *this);
    }

    template <typename StreamType>
    static Share load(int64_t version, StreamType& is)
    {
        Share share;
        share = new A();
        share.unpack(is);

        return share;
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
            m_func(share, m_stream);
            return *this;    
        }
    };

    template <typename StreamType>
    StreamType& unpack(StreamType& is)
    {
        // auto wrap = std::visit(Wrapper(is), *this);
        return invoke(Wrapper(is, [](auto* share, auto& stream){ stream.m_counter++; })).m_stream;
        // return wrap.m_stream;

        // StreamType& result = std::visit([=](auto* share)-> auto& { return is; }, *this);
        // return result;
        // auto&& f = [&](auto* share) { /*return Formatter::pack_share(is, share);*/ };
        // invoke(std::move(f));
    }

    template <typename T>
    Share& operator=(T* value)
    {
        // static_assert((std::is_same_v<T, Args> || ...), "ShareVariants can be cast only to Args...");
        std::variant<A*>::operator = (value);
        return *this;
    }
};

template <typename StreamType>
inline Share load(int64_t version, StreamType& is, int peer_addr)
{
    auto share = Share::load(version, is);
    // share.ACTION({ obj->peer_addr = peer_addr; });
    return share;
}

int main()
{
    RawShare wrappedshare(10, {});
    auto share = load(wrappedshare.type, wrappedshare.contents, 100);
    std::cout << wrappedshare.contents.m_counter << std::endl;
}