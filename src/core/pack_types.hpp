#pragma once

#include <array>

#include "pack.hpp"
#include <btclibs/uint256.h>

template <size_t Size>
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
        std::array<std::byte, Size> arr;
        s.read(std::as_writable_bytes(std::span{arr}));

        PackStream reverse_stream(arr);
        reverse_stream.reverse();
        // std::reverse(arr.begin(), arr.end());

        reverse_stream >> t;
        // s.write(r);

        // std::reverse(r.begin(), r.end());
        // PackStream reverse_stream;
        // reverse_stream.read(r);

        // reverse_stream >> t;
    }
};

// BE -- Big Endian
template <typename int_type, bool BE = false>
struct UIntType
{
    static void Write(PackStream& os, const int_type& value)
    {
        if constexpr (BE)
        {
            os << Using<BigEndianFormat<sizeof(int_type)>>(value);
        } else 
        {
            os << value;
        }
    }

    static void Read(PackStream& is, int_type& value)
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
    static void Write(PackStream& os, const long_type& value)
    {
        if constexpr (BE)
        {
            os << Using<BigEndianFormat<long_type::BYTES>>(value);
        } else 
        {
            os << value;
        }
    }

    static void Read(PackStream& is, long_type& value)
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

template <typename INT_PACK_TYPE>
struct EnumType
{
    template <typename E>
    static void Write(PackStream& os, const E& enum_value)
    {
        static_assert(std::is_enum<E>::value, "EnumType::Write needs for enum value");
        os << Using<INT_PACK_TYPE>(enum_value);
    }

    template <typename E>
    static void Read(PackStream& is, E& enum_value)
    {
        static_assert(std::is_enum<E>::value, "EnumType::Read needs for enum value");
        typename INT_PACK_TYPE::num_type res;
        is >> Using<INT_PACK_TYPE>(res);

        enum_value = (E)res;
    }
};