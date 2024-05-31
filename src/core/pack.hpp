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
        std::cout << "{ ";
        for (auto const b : m_vch)
            std::cout << std::setw(2) << std::to_integer<int>(b) << ' ';
        std::cout << std::dec << "}\n";
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

void WriteCompactSize(PackStream& os, uint64_t nSize)
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

uint64_t ReadCompactSize(PackStream& is, bool range_check = true)
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