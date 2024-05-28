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

    void print() const
    {
        std::cout << "{ ";
        for (auto const b : m_vch)
            std::cout << std::setw(2) << std::to_integer<int>(b) << ' ';
        std::cout << std::dec << "}\n";
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

    template <typename T>
    PackStream& operator<<(const T& v)
    {
        T::serialize(*this, v);
        return *this;
    }
};

/**
 * Convert any argument to a reference to X, maintaining constness.
 *
 * This can be used in serialization code to invoke a base class's
 * serialization routines.
 *
 * Example use:
 *   class Base { ... };
 *   class Child : public Base {
 *     int m_data;
 *   public:
 *     SERIALIZE_METHODS(Child, obj) {
 *       READWRITE(AsBase<Base>(obj), obj.m_data);
 *     }
 *   };
 *
 * static_cast cannot easily be used here, as the type of Obj will be const Child&
 * during serialization and Child& during deserialization. AsBase will convert to
 * const Base& and Base& appropriately.
 */
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

#define READWRITE(...) (ser_action.SerReadWriteMany(s, __VA_ARGS__))
#define SER_READ(obj, code) ser_action.SerRead(s, obj, [&](Stream& s, typename std::remove_const<Type>::type& obj) { code; })
#define SER_WRITE(obj, code) ser_action.SerWrite(s, obj, [&](Stream& s, const Type& obj) { code; })

/**
 * Implement the Ser and Unser methods needed for implementing a formatter (see Using below).
 *
 * Both Ser and Unser are delegated to a single static method SerializationOps, which is polymorphic
 * in the serialized/deserialized type (allowing it to be const when serializing, and non-const when
 * deserializing).
 *
 * Example use:
 *   struct FooFormatter {
 *     FORMATTER_METHODS(Class, obj) { READWRITE(obj.val1, VARINT(obj.val2)); }
 *   }
 *   would define a class FooFormatter that defines a serialization of Class objects consisting
 *   of serializing its val1 member using the default serialization, and its val2 member using
 *   VARINT serialization. That FooFormatter can then be used in statements like
 *   READWRITE(Using<FooFormatter>(obj.bla)).
 */
#define FORMATTER_METHODS(cls, obj) \
    template<typename Stream> \
    static void Ser(Stream& s, const cls& obj) { SerializationOps(obj, s, ActionSerialize{}); } \
    template<typename Stream> \
    static void Unser(Stream& s, cls& obj) { SerializationOps(obj, s, ActionUnserialize{}); } \
    template<typename Stream, typename Type, typename Operation> \
    static void SerializationOps(Type& obj, Stream& s, Operation ser_action)

/**
 * Formatter methods can retrieve parameters attached to a stream using the
 * SER_PARAMS(type) macro as long as the stream is created directly or
 * indirectly with a parameter of that type. This permits making serialization
 * depend on run-time context in a type-safe way.
 *
 * Example use:
 *   struct BarParameter { bool fancy; ... };
 *   struct Bar { ... };
 *   struct FooFormatter {
 *     FORMATTER_METHODS(Bar, obj) {
 *       auto& param = SER_PARAMS(BarParameter);
 *       if (param.fancy) {
 *         READWRITE(VARINT(obj.value));
 *       } else {
 *         READWRITE(obj.value);
 *       }
 *     }
 *   };
 * which would then be invoked as
 *   READWRITE(BarParameter{...}(Using<FooFormatter>(obj.foo)))
 *
 * parameter(obj) can be invoked anywhere in the call stack; it is
 * passed down recursively into all serialization code, until another
 * serialization parameter overrides it.
 *
 * Parameters will be implicitly converted where appropriate. This means that
 * "parent" serialization code can use a parameter that derives from, or is
 * convertible to, a "child" formatter's parameter type.
 *
 * Compilation will fail in any context where serialization is invoked but
 * no parameter of a type convertible to BarParameter is provided.
 */
#define SER_PARAMS(type) (s.template GetParams<type>())

#define BASE_SERIALIZE_METHODS(cls)                                                                 \
    template <typename Stream>                                                                      \
    void Serialize(Stream& s) const                                                                 \
    {                                                                                               \
        static_assert(std::is_same<const cls&, decltype(*this)>::value, "Serialize type mismatch"); \
        Ser(s, *this);                                                                              \
    }                                                                                               \
    template <typename Stream>                                                                      \
    void Unserialize(Stream& s)                                                                     \
    {                                                                                               \
        static_assert(std::is_same<cls&, decltype(*this)>::value, "Unserialize type mismatch");     \
        Unser(s, *this);                                                                            \
    }

/**
 * Implement the Serialize and Unserialize methods by delegating to a single templated
 * static method that takes the to-be-(de)serialized object as a parameter. This approach
 * has the advantage that the constness of the object becomes a template parameter, and
 * thus allows a single implementation that sees the object as const for serializing
 * and non-const for deserializing, without casts.
 */
#define SERIALIZE_METHODS(cls, obj) \
    BASE_SERIALIZE_METHODS(cls)     \
    FORMATTER_METHODS(cls, obj)


// serialize int data
template<typename Stream> inline void ser_writedata8(Stream &s, uint8_t obj)
{
    s.write(std::as_bytes(std::span<uint8_t>{&obj, 1}));
}

template<typename Stream> inline void ser_writedata16(Stream &s, uint16_t obj)
{
    // obj = htole16(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata16be(Stream &s, uint16_t obj)
{
    // obj = htobe16(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata32(Stream &s, uint32_t obj)
{
    // obj = htole32(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata32be(Stream &s, uint32_t obj)
{
    // obj = htobe32(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata64(Stream &s, uint64_t obj)
{
    // obj = htole64(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline uint8_t ser_readdata8(Stream &s)
{
    uint8_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return obj;
}

template<typename Stream> inline uint16_t ser_readdata16(Stream &s)
{
    uint16_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    // return le16toh(obj);
    return obj;
}

template<typename Stream> inline uint16_t ser_readdata16be(Stream &s)
{
    uint16_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    // return be16toh(obj);
    return obj;
}

template<typename Stream> inline uint32_t ser_readdata32(Stream &s)
{
    uint32_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    // return le32toh(obj);
    return obj;
}

template<typename Stream> inline uint32_t ser_readdata32be(Stream &s)
{
    uint32_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    // return be32toh(obj);
    return obj;
}

template<typename Stream> inline uint64_t ser_readdata64(Stream &s)
{
    uint64_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    // return le64toh(obj);
    return obj;
}

void WriteCompactSize(PackStream& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        ser_writedata8(os, nSize);
    }
    else if (nSize <= std::numeric_limits<uint16_t>::max())
    {
        ser_writedata8(os, 253);
        ser_writedata16(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata8(os, 254);
        ser_writedata32(os, nSize);
    }
    else
    {
        ser_writedata8(os, 255);
        ser_writedata64(os, nSize);
    }
    return;
}

uint64_t ReadCompactSize(PackStream& is, bool range_check = true)
{
    uint8_t chSize = ser_readdata8(is);
    uint64_t nSizeRet = 0;
    if (chSize < 253)
    {
        nSizeRet = chSize;
    }
    else if (chSize == 253)
    {
        nSizeRet = ser_readdata16(is);
        if (nSizeRet < 253)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else if (chSize == 254)
    {
        nSizeRet = ser_readdata32(is);
        if (nSizeRet < 0x10000u)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else
    {
        nSizeRet = ser_readdata64(is);
        if (nSizeRet < 0x100000000ULL)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    if (range_check && nSizeRet > MAX_SIZE) {
        throw std::ios_base::failure("ReadCompactSize(): size too large");
    }
    return nSizeRet;
}

/**
 * Support for (un)serializing many things at once
 */

template <typename Stream, typename... Args>
void SerializeMany(Stream& s, const Args&... args)
{
    (::Serialize(s, args), ...);
}

template <typename Stream, typename... Args>
inline void UnserializeMany(Stream& s, Args&&... args)
{
    (::Unserialize(s, args), ...);
}

/**
 * Support for all macros providing or using the ser_action parameter of the SerializationOps method.
 */
struct ActionSerialize {
    static constexpr bool ForRead() { return false; }

    template<typename Stream, typename... Args>
    static void SerReadWriteMany(Stream& s, const Args&... args)
    {
        ::SerializeMany(s, args...);
    }

    template<typename Stream, typename Type, typename Fn>
    static void SerRead(Stream& s, Type&&, Fn&&)
    {
    }

    template<typename Stream, typename Type, typename Fn>
    static void SerWrite(Stream& s, Type&& obj, Fn&& fn)
    {
        fn(s, std::forward<Type>(obj));
    }
};
struct ActionUnserialize {
    static constexpr bool ForRead() { return true; }

    template<typename Stream, typename... Args>
    static void SerReadWriteMany(Stream& s, Args&&... args)
    {
        ::UnserializeMany(s, args...);
    }

    template<typename Stream, typename Type, typename Fn>
    static void SerRead(Stream& s, Type&& obj, Fn&& fn)
    {
        fn(s, std::forward<Type>(obj));
    }

    template<typename Stream, typename Type, typename Fn>
    static void SerWrite(Stream& s, Type&&, Fn&&)
    {
    }
};