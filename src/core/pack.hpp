#pragma once

#include <iostream>
#include <span>
#include <array>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>
#include <string>
#include <limits>

/**
 * The maximum size of a serialized object in bytes or number of elements
 * (for eg vectors) when the size is encoded as CompactSize.
 */
static constexpr uint64_t MAX_SIZE = 0x02000000;

/** Maximum amount of memory (in bytes) to allocate at once when deserializing vectors. */
static const unsigned int MAX_VECTOR_ALLOCATE = 5000000;

template <typename RealType>
struct PackType
{
    using type = RealType;
};

struct PackStream
{
protected:
    std::vector<std::byte> m_vch;
    std::vector<std::byte>::size_type m_cursor{0};

public:
    explicit PackStream() {}
    // explicit PackStream(std::span<const uint8_t> sp) { write(sp); }
    explicit PackStream(std::span<const std::byte> sp) : m_vch(sp.data(), sp.data() + sp.size()) {}
    template <size_t Size>
    explicit PackStream(std::array<std::byte, Size> arr) : m_vch(arr.begin(), arr.end()) { }

    void write(std::span<const std::byte> value)
    {
        m_vch.insert(m_vch.end(), value.begin(), value.end());
    }

    void read(const std::span<std::byte>& data)
    {
        if (data.empty()) return;

        auto new_cursor_pos = m_cursor + data.size();
        if (new_cursor_pos > m_vch.size())
            throw std::ios_base::failure("PackStream::read(): end of data!");

        memcpy(data.data(), &m_vch[m_cursor], data.size());
        if (new_cursor_pos == m_vch.size()) 
        {
            m_cursor = 0;
            m_vch.clear();
            return;
        }

        m_cursor = new_cursor_pos;
    }

    std::vector<std::byte>::pointer data()
    {
        return m_vch.data();
    }

    // stored data size
    size_t size() const
    {
        return m_vch.size();
    }

    // size from cursor
    size_t cursor_size() const
    {
        return m_vch.size() - m_cursor;
    }

    void print() const
    {
        std::cout << "{ " << std::hex;
        for (auto const b : m_vch)
            std::cout << std::setw(2) << std::to_integer<int>(b) << ' ';
        std::cout << std::dec << "}\n";
    }

    void reverse()
    {
        std::reverse(m_vch.begin(), m_vch.end());
    }

    template <typename T>
    PackStream& operator<<(const T& value)
    {
        Serialize(*this, value);
        return *this;
    }

    template <typename T>
    PackStream& operator>>(T&& value)
    {
        Unserialize(*this, value);
        return *this;
    }

    friend inline void Serialize(PackStream& to, const PackStream& from)
    {
        to.m_vch.insert(to.m_vch.end(), std::make_move_iterator(from.m_vch.begin()), std::make_move_iterator(from.m_vch.end()));
    }

    friend inline void Unserialize(const PackStream& from, PackStream& to)
    {
        to.m_vch.insert(to.m_vch.end(), std::make_move_iterator(from.m_vch.begin()), std::make_move_iterator(from.m_vch.end()));
    }
};

template <typename ParamsType, typename StreamType>
struct ParamPackStream
{
    const ParamsType m_params;
    StreamType& m_stream;

public:
    explicit ParamPackStream(const ParamsType& params, StreamType& stream) : m_params(params), m_stream(stream) { }

    void write(std::span<const std::byte> value) { m_stream.write(value); }
    void read(const std::span<std::byte>& data) { m_stream.read(data); }

    template <typename T>
    ParamPackStream& operator<<(const T& value)
    {
        Serialize(*this, value);
        return *this;
    }

    template <typename T>
    ParamPackStream& operator>>(T&& value)
    {
        Unserialize(*this, value);
        return *this;
    }
    
    const ParamsType& GetParams() const { return m_params; }
};

struct SerializeFormatter
{
    template <typename StreamType, typename... Args>
    static void action(StreamType& stream, Args&&...args)
    {
        // SerializeAction(stream, args...);
        (Serialize(stream, args), ...);
    }
};

struct UnserializeFormatter
{
    template <typename StreamType, typename... Args>
    static void action(StreamType& stream, Args&&...args)
    {
        // UnserializeAction(stream, args...);
        (Unserialize(stream, args), ...);
    }
};

template <class Out, class In>
Out& AsBase(In& x)
{
    static_assert(std::is_base_of_v<Out, In>);
    return x;
}
template <class Out, class In>
const Out& AsBase(const In& x)
{
    static_assert(std::is_base_of_v<Out, In>);
    return x;
}

#define READWRITE(...) formatter.action(stream, __VA_ARGS__)

#define FORMAT_METHODS(TYPE)\
    template<typename StreamType>\
    static void Write(StreamType &stream, const TYPE &obj) { FormatAction(stream, obj, SerializeFormatter{}); }\
    template<typename StreamType>\
    static void Read(StreamType &stream, TYPE &obj) { FormatAction(stream, obj, UnserializeFormatter{}); }\
    template<typename StreamType, typename Type, typename Formatter>\
    static void FormatAction(StreamType &stream, Type &obj, Formatter formatter)

#define BASE_SERIALIZE_METHODS(TYPE)\
    template<typename StreamType>\
    void Serialize(StreamType& os) const\
    {\
        static_assert(std::is_same_v<const TYPE&, decltype(*this)>, "Serialize " #TYPE " missmatch");\
        Write(os, *this);\
    }\
    template<typename StreamType>\
    void Unserialize(StreamType& is)\
    {\
        static_assert(std::is_same_v<TYPE&, decltype(*this)>, "Unserialize " #TYPE " missmatch");\
        Read(is, *this);\
    }

#define SERIALIZE_METHODS(TYPE)\
    BASE_SERIALIZE_METHODS(TYPE)\
    FORMAT_METHODS(TYPE)

// serialize int data
template <typename T>
concept IsInteger = std::numeric_limits<T>::is_integer;

template <typename StreamType, IsInteger int_type>
inline void Serialize(StreamType& os, const int_type& value)
{
    os.write(std::as_bytes(std::span{&value, 1}));
}

template <typename StreamType, IsInteger int_type>
inline void Unserialize(StreamType& is, int_type& value)
{
    is.read(std::as_writable_bytes(std::span{&value, 1}));
}

template <IsInteger int_type, typename StreamType>
inline void write_int(StreamType& os, int_type num)
{
    Serialize(os, num);
}

template <IsInteger int_type, typename StreamType>
inline int_type read_int(StreamType& is)
{
    int_type num;
    Unserialize(is, num);
    return num;
}

template <typename StreamType>
inline void WriteCompactSize(StreamType& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        write_int<uint8_t>(os, nSize);
    }
    else if (nSize <= std::numeric_limits<uint16_t>::max())
    {
        write_int<uint8_t>(os, 253);
        write_int<uint16_t>(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        write_int<uint8_t>(os, 254);
        write_int<uint32_t>(os, nSize);
    }
    else
    {
        write_int<uint8_t>(os, 255);
        write_int<uint64_t>(os, nSize);
    }
    return;
}

template <typename StreamType>
inline uint64_t ReadCompactSize(StreamType& is, bool range_check = true)
{
    uint8_t chSize = read_int<uint8_t>(is);
    
    uint64_t nSizeRet = 0;
    if (chSize < 253)
    {
        nSizeRet = chSize;
    }
    else if (chSize == 253)
    {
        nSizeRet = read_int<uint16_t>(is);
        if (nSizeRet < 253)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else if (chSize == 254)
    {
        nSizeRet = read_int<uint32_t>(is);
        if (nSizeRet < 0x10000u)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else
    {
        nSizeRet = read_int<uint64_t>(is);
        if (nSizeRet < 0x100000000ULL)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    if (range_check && nSizeRet > MAX_SIZE) {
        throw std::ios_base::failure("ReadCompactSize(): size too large");
    }
    return nSizeRet;
}

// serialize string data
template <typename StreamType>
inline void Serialize(StreamType& os, const std::string& value)
{
    WriteCompactSize(os, value.size());
    os.write(std::as_bytes(std::span{value}));
}

template <typename StreamType>
inline void Unserialize(StreamType& is, std::string& value)
{
    auto size = ReadCompactSize(is);
    value.resize(size);
    is.read(std::as_writable_bytes(std::span{&value[0], size}));
}

/**
 * If none of the specialized versions above matched, default to calling member function.
 */
template <typename StreamType, class T>
concept Serializable = requires(T a, StreamType& s) { a.Serialize(s); };
template <typename StreamType, typename T> requires Serializable<StreamType, T>
void Serialize(StreamType& os, const T& a)
{
    a.Serialize(os);
}

template <typename StreamType, class T>
concept Unserializable = requires(T a, StreamType& s) { a.Unserialize(s); };
template <typename StreamType, typename T> requires Unserializable<StreamType, T>
void Unserialize(StreamType& is, T&& a)
{
    a.Unserialize(is);
}

template <typename T>
concept is_packstream_type = Serializable<PackStream, T> && Unserializable<PackStream, T>;

template <typename PackFormat, typename T>
class Wrapper
{
    static_assert(std::is_lvalue_reference<T>::value, "Wrapper needs an lvalue reference type T");
protected:
    T m_value;

public:
    explicit Wrapper(T value) : m_value(value) { }

    template <typename StreamType>
    void Serialize(StreamType& os) const
    {
        PackFormat::Write(os, m_value);
    }

    template <typename StreamType>
    void Unserialize(StreamType& is)
    {
        PackFormat::Read(is, m_value);
    }
};

template <typename PackFormat, typename T>
static inline Wrapper<PackFormat, T> Using(T&& value) { return Wrapper<PackFormat, T&>(value); }

/** Default formatter. Serializes objects as themselves.
 *
 * The vector/prevector serialization code passes this to VectorFormatter
 * to enable reusing that logic. It shouldn't be needed elsewhere.
 */
struct DefaultFormat
{
    template<typename StreamType, typename T>
    static void Write(StreamType& s, const T& t) { Serialize(s, t); }

    template<typename StreamType, typename T>
    static void Read(StreamType& s, T& t) { Unserialize(s, t); }
};


template <typename PackFormat>
struct ListType
{
    template <typename StreamType, typename V>
    static void Write(StreamType& os, const V& values)
    {
        WriteCompactSize(os, values.size());

        for(const typename V::value_type& v : values)
        {
            PackFormat::Write(os, v);
        }
    }

    template <typename StreamType, typename V>
    static void Read(StreamType& is, V& values)
    {
        values.clear();
        auto nSize = ReadCompactSize(is);
        size_t allocated = 0;
        while (allocated < nSize) 
        {
            // For DoS prevention, do not blindly allocate as much as the stream claims to contain.
            // Instead, allocate in 5MiB batches, so that an attacker actually needs to provide
            // X MiB of data to make us allocate X+5 Mib.
            static_assert(sizeof(typename V::value_type) <= MAX_VECTOR_ALLOCATE, "Vector element size too large");
            allocated = std::min(nSize, allocated + MAX_VECTOR_ALLOCATE / sizeof(typename V::value_type));
            values.reserve(allocated);
            while (values.size() < allocated) 
            {
                values.emplace_back();
                PackFormat::Read(is, values.back());
            }
        }
    }
};

/**
 * vector
 */
template <typename StreamType, typename T>
void Serialize(StreamType& os, const std::vector<T>& v)
{
    /*  TODO:
    if constexpr (BasicByte<T>) { // Use optimized version for unformatted basic bytes
        WriteCompactSize(os, v.size());
        if (!v.empty()) os.write(MakeByteSpan(v));
    } else if constexpr (std::is_same_v<T, bool>) {
        // A special case for std::vector<bool>, as dereferencing
        // std::vector<bool>::const_iterator does not result in a const bool&
        // due to std::vector's special casing for bool arguments.
        WriteCompactSize(os, v.size());
        for (bool elem : v) {
            Serialize(os, elem);
        }
    } else */ 
    {
        Serialize(os, Using<ListType<DefaultFormat>>(v));
    }
}

template <typename StreamType, typename T, typename A>
void Unserialize(StreamType& is, std::vector<T, A>& v)
{
    /* TODO:
    if constexpr (BasicByte<T>) { // Use optimized version for unformatted basic bytes
        // Limit size per read so bogus size value won't cause out of memory
        v.clear();
        unsigned int nSize = ReadCompactSize(is);
        unsigned int i = 0;
        while (i < nSize) {
            unsigned int blk = std::min(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
            v.resize(i + blk);
            is.read(AsWritableBytes(Span{&v[i], blk}));
            i += blk;
        }
    } else */
    {
        Unserialize(is, Using<ListType<DefaultFormat>>(v));
    }
}

template <typename ParamsType, typename T>
class ParamsWrapper
{
    const ParamsType& m_params;
    T& m_value;

public:
    explicit ParamsWrapper(const ParamsType& params, T& value) : m_params(params), m_value(value) { }

    template <typename StreamType>
    void Serialize(StreamType& os) const
    {
        ParamPackStream stream{m_params, os};
        ::Serialize(stream, m_value);
    }

    template <typename StreamType>
    void Unserialize(StreamType& is)
    {
        ParamPackStream stream{m_params, is};
        ::Unserialize(stream, m_value);
    }
};

#define SER_PARAMS_OPFUNC                                                                \
    template <typename T>                                                                \
    auto operator()(T&& t) const                                                         \
    {                                                                                    \
        return ParamsWrapper{*this, t};                                                  \
    }

template<typename T>
PackStream pack(const T& value)
{
    PackStream stream;
    stream << value;
    return stream;
}