#pragma once

#include <optional>
#include <array>

#include "pack.hpp"
#include <core/uint256.hpp>

template <size_t Size>
struct BigEndianFormat
{
    template<typename StreamType, typename T>
    static void Write(StreamType& s, const T& t) 
    { 
        PackStream reverse_stream;
        reverse_stream << t;
        reverse_stream.reverse();

        s << reverse_stream;
    }

    template<typename StreamType, typename T>
    static void Read(StreamType& s, T& t) 
    {
        std::array<std::byte, Size> arr;
        s.read(std::as_writable_bytes(std::span{arr}));

        PackStream reverse_stream(arr);
        reverse_stream.reverse();

        reverse_stream >> t;
    }
};

// BE -- Big Endian
template <typename int_type, bool BE = false>
struct UIntType
{
    template <typename StreamType>
    static void Write(StreamType& os, const int_type& value)
    {
        if constexpr (BE)
        {
            os << Using<BigEndianFormat<sizeof(int_type)>>(value);
        } else 
        {
            os << value;
        }
    }

    template <typename StreamType>
    static void Read(StreamType& is, int_type& value)
    {
        if constexpr (BE)
        {
            is >> Using<BigEndianFormat<sizeof(int_type)>>(value);
        } else 
        {
            is >> value;
        }
    }
};

template <typename long_type, bool BE = false>
struct ULongType
{
    // static_assert(std::is_base_of<base_uint<>, long_type>::value, "ULongType want for base_uint type!");
    template <typename StreamType>
    static void Write(StreamType& os, const long_type& value)
    {
        if constexpr (BE)
        {
            os << Using<BigEndianFormat<long_type::BYTES>>(value);
        } else 
        {
            os << value;
        }
    }

    template <typename StreamType>
    static void Read(StreamType& is, long_type& value)
    {
        if constexpr (BE)
        {
            is >> Using<BigEndianFormat<long_type::BYTES>>(value);
        } else 
        {
            is >> value;
        }
    }
};

template <int N, bool BE = false>
struct IntType;

#define INT_TYPE_SPEC(N, PARENT_TYPE, CHILD_TYPE)\
    template<bool BE> struct IntType<N, BE> : public PARENT_TYPE < CHILD_TYPE , BE > { using num_type = CHILD_TYPE; };

INT_TYPE_SPEC(8, UIntType, uint8_t);
INT_TYPE_SPEC(16, UIntType, uint16_t);
INT_TYPE_SPEC(32, UIntType, uint32_t);
INT_TYPE_SPEC(64, UIntType, uint64_t);

INT_TYPE_SPEC(128, ULongType, uint128);
INT_TYPE_SPEC(160, ULongType, uint160);
INT_TYPE_SPEC(256, ULongType, uint256);
INT_TYPE_SPEC(288, ULongType, uint288);
#undef INT_TYPE_SPEC

template <typename PackFormat, size_t Size>
struct ArrayType
{
    template <typename StreamType, typename V>
    static void Write(StreamType& os, const V& values)
    {
        for(const typename V::value_type& v : values)
        {
            PackFormat::Write(os, v);
        }
    }

    template <typename StreamType, typename V>
    static void Read(StreamType& is, V& values)
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

// example using: Using<EnumType<IntType<8>>>(obj->m_stale_info)
template <typename INT_PACK_TYPE>
struct EnumType
{
    template <typename StreamType, typename E>
    static void Write(StreamType& os, const E& enum_value)
    {
        static_assert(std::is_enum<E>::value, "EnumType::Write needs for enum value");
        os << Using<INT_PACK_TYPE>(enum_value);
    }

    template <typename StreamType, typename E>
    static void Read(StreamType& is, E& enum_value)
    {
        static_assert(std::is_enum<E>::value, "EnumType::Read needs for enum value");
        typename INT_PACK_TYPE::num_type res;
        is >> Using<INT_PACK_TYPE>(res);

        enum_value = (E)res;
    }
};

struct CompactFormat
{
    using num_type = uint32_t;

    template <typename StreamType, typename int_type>
    static void Write(StreamType& os, const int_type& num)
    {
        WriteCompactSize(os, num);
    }

    template <typename StreamType, typename int_type>
    static void Read(StreamType& os, int_type& num)
    {
        num = ReadCompactSize(os, false);
    }
};

template <class T>
concept OptionalTypeDefault = requires 
{
    T::get();
}; //(T a, PackStream& s) { a.Serialize(s); };

template <OptionalTypeDefault Default>
struct OptionalType
{
    template <typename StreamType, typename T>
    static void Write(StreamType& os, const std::optional<T>& opt)
    {
        if (opt)
            os << *opt;
        else
            os << Default::get();
    }

    template <typename StreamType, typename T>
    static void Read(StreamType& os, std::optional<T>& opt)
    {
        T result;
        os >> result;
        opt = result;
    }
};

struct BaseScript
{
    using data_t = std::vector<unsigned char>;
    using const_iterator = data_t::const_iterator;
    std::vector<unsigned char> m_data;

    BaseScript() : m_data() { }
    BaseScript(data_t data) : m_data(data) { }
    BaseScript(std::string str) : m_data(str.begin(), str.end()) { }
    BaseScript(const_iterator pbegin, const_iterator pend) : m_data(pbegin, pend) { }
    BaseScript(const unsigned char* pbegin, const unsigned char* pend) : m_data(pbegin, pend) { }
    BaseScript(PackStream& stream) : m_data((unsigned char*)*stream.begin(), (unsigned char*)*stream.end()) { }

    PackStream as_stream()
    {
        return PackStream(m_data);
    }

    size_t size() const
    {
        return m_data.size();
    }

    friend bool operator==(const BaseScript& l, const BaseScript& r) { return l.m_data == r.m_data; }
    friend bool operator!=(const BaseScript& l, const BaseScript& r) { return !(l==r); }

    SERIALIZE_METHODS(BaseScript) { READWRITE(obj.m_data); }
};

template <size_t Size>
struct FixedStrType : BaseScript
{
    static constexpr int fixed_size = Size;

    FixedStrType() : BaseScript() { }
    FixedStrType(std::string str) : BaseScript(str) { } //BaseScript((const unsigned char*)str.data(), (const unsigned char*)str.data() + str.size()) { }

    std::string ToString()
    {
        return std::string(m_data.begin(), m_data.end());
    }

    friend bool operator==(const FixedStrType<Size>& l, const FixedStrType<Size>& r) { return l.m_data == r.m_data; }
    friend bool operator!=(const FixedStrType<Size>& l, const FixedStrType<Size>& r) { return !(l==r); }

    template <typename StreamType>
    void Serialize(StreamType &os) const
    {
        static_assert(std::is_same_v<const FixedStrType<Size> &, decltype(*this)>, "Serialize FixedStrType<Size> missmatch");
        for (auto &chr : m_data)
            os << chr;
    }

    template <typename StreamType>
    void Unserialize(StreamType &is)
    {
        static_assert(std::is_same_v<FixedStrType<Size> &, decltype(*this)>, "Unserialize FixedStrType<Size> missmatch");
        
        m_data.resize(Size);
        for (auto &chr : m_data)
            is >> chr;
    }
};

#define Optional(obj, Default) Using<OptionalType<Default>>(obj)
#define VarInt(obj) Using<CompactFormat>(obj)