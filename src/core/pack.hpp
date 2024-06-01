#pragma once

#include <iostream>
#include <span>
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

struct SerializeFormatter
{
    template <typename... Args>
    static void action(PackStream& stream, Args&&...args)
    {
        // SerializeAction(stream, args...);
        (Serialize(stream, args), ...);
    }
};

struct UnserializeFormatter
{
    template <typename... Args>
    static void action(PackStream& stream, Args&&...args)
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
    static void Write(PackStream &stream, const TYPE &obj) { FormatAction(stream, obj, SerializeFormatter{}); }\
    static void Read(PackStream &stream, TYPE &obj) { FormatAction(stream, obj, UnserializeFormatter{}); }\
    template<typename Type, typename Formatter>\
    static void FormatAction(PackStream &stream, Type &obj, Formatter formatter)

#define BASE_SERIALIZE_METHODS(TYPE)\
    void Serialize(PackStream& os) const\
    {\
        static_assert(std::is_same_v<const TYPE&, decltype(*this)>, "Serialize " #TYPE " missmatch");\
        Write(os, *this);\
    }\
    void Unserialize(PackStream& is)\
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

template <IsInteger int_type>
inline void Serialize(PackStream& os, const int_type& value)
{
    os.write(std::as_bytes(std::span{&value, 1}));
}

template <IsInteger int_type>
inline void Unserialize(PackStream& is, int_type& value)
{
    is.read(std::as_writable_bytes(std::span{&value, 1}));
}

template <IsInteger int_type>
inline void write_int(PackStream& os, int_type num)
{
    Serialize(os, num);
}

template <IsInteger int_type>
inline int_type read_int(PackStream& is)
{
    int_type num;
    Unserialize(is, num);
    return num;
}

inline void WriteCompactSize(PackStream& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        write_int<uint8_t>(os, nSize);
    }
    else if (nSize <= std::numeric_limits<uint16_t>::max())
    {
        write_int<uint8_t>(os, nSize);
        write_int<uint16_t>(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        write_int<uint8_t>(os, nSize);
        write_int<uint32_t>(os, nSize);
    }
    else
    {
        write_int<uint8_t>(os, nSize);
        write_int<uint64_t>(os, nSize);
    }
    return;
}

inline uint64_t ReadCompactSize(PackStream& is, bool range_check = true)
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

inline void Serialize(PackStream& os, const std::string& value)
{
    WriteCompactSize(os, value.size());
    os.write(std::as_bytes(std::span{value}));
}

inline void Unserialize(PackStream& is, std::string& value)
{
    auto size = ReadCompactSize(is);
    value.resize(size);
    is.read(std::as_writable_bytes(std::span{&value[0], size}));
}

/**
 * If none of the specialized versions above matched, default to calling member function.
 */
template <class T>
concept Serializable = requires(T a, PackStream& s) { a.Serialize(s); };
template <typename T> requires Serializable<T>
void Serialize(PackStream& os, const T& a)
{
    a.Serialize(os);
}

template <class T>
concept Unserializable = requires(T a, PackStream& s) { a.Unserialize(s); };
template <typename T> requires Unserializable<T>
void Unserialize(PackStream& is, T&& a)
{
    a.Unserialize(is);
}

template <typename PackFormat, typename T>
class Wrapper
{
    static_assert(std::is_lvalue_reference<T>::value, "Wrapper needs an lvalue reference type T");
protected:
    T m_value;

public:
    Wrapper(T value) : m_value(value) { }

    void Serialize(PackStream& os) const
    {
        PackFormat::Write(os, m_value);
    }

    void Unserialize(PackStream& is)
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
    template<typename T>
    static void Write(PackStream& s, const T& t) { Serialize(s, t); }

    template<typename T>
    static void Read(PackStream& s, T& t) { Unserialize(s, t); }
};

template <std::size_t Size>
struct BigEndianFormat
{
    template<typename T>
    static void Write(PackStream& s, const T& t) 
    { 
        PackStream reverse_stream;
        reverse_stream << t;
        reverse_stream.reverse();

        s << reverse_stream;        
    }

    template<typename T>
    static void Read(PackStream& s, T& t) 
    {
        std::as_writable_bytes(std::span{&value, 1})
        std::span<std::byte> r;
        s.write(r);

        std::reverse(r.begin(), r.end());
        PackStream reverse_stream;
        reverse_stream.read(r);

        reverse_stream >> t;
    }
};

// BE -- Big Endian
template <typename int_type, bool BE = false>
struct IntType
{
    static void Write(PackStream& os, const int_type& value)
    {
        if constexpr (BE)
        {
            os << Using<BigEndianFormat<4>>(value);
        } else 
        {
            os << value;
        }
    }

    static void Read(PackStream& is, int_type& value)
    {
        if constexpr (BE)
        {
            is >> Using<BigEndianFormat<4>>(value);
        } else 
        {
            is >> value;
        }
    }
};

template <typename PackFormat>
struct ListType
{
    template <typename V>
    static void Write(PackStream& os, const V& values)
    {
        WriteCompactSize(os, values.size());

        for(const typename V::value_type& v : values)
        {
            PackFormat::Write(os, v);
        }
    }

    template <typename V>
    static void Read(PackStream& is, V& values)
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

template <typename PackFormat, size_t Size>
struct ArrayType
{
    template <typename V>
    static void Write(PackStream& os, const V& values)
    {
        for(const typename V::value_type& v : values)
        {
            PackFormat::Write(os, v);
        }
    }

    template <typename V>
    static void Read(PackStream& is, V& values)
    {
        values.clear();
        values.reserve(Size);
        for (int i = 0; i < Size; i++)
        {
            values.emplace_back();
            PackFormat::Read(is, values.back());
        }
    }
};

/**
 * vector
 */
template <typename T>
void Serialize(PackStream& os, const std::vector<T>& v)
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
    } else */ {
        Serialize(os, Using<ListType<DefaultFormat>>(v));
    }
}

template <typename T, typename A>
void Unserialize(PackStream& is, std::vector<T, A>& v)
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
    } else */{
        Unserialize(is, Using<ListType<DefaultFormat>>(v));
    }
}