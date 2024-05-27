#pragma once
#include "packv2.hpp"

// int
template <typename int_type>
struct _IntType
{
    static void serialize(PackStream& os, int_type& value)
    {
        os.write(std::as_bytes(std::span{&value, 1}));
    }

    static void unserialize(PackStream& is, int_type& value)
    {

        is.read(std::as_writable_bytes(std::span{&value, 1}));
    }
};

template <int N>
struct IntTypeSpecificator;

#define INT_TYPE_SPEC(N, PARENT_TYPE, CHILD_TYPE)\
    template<> struct IntTypeSpecificator<N> { using type = PARENT_TYPE < CHILD_TYPE >; }

INT_TYPE_SPEC(16, _IntType, int16_t);
INT_TYPE_SPEC(32, _IntType, int32_t);
INT_TYPE_SPEC(64, _IntType, int64_t);
#undef INT_TYPE_SPEC

template <int N>
using IntType = IntTypeSpecificator<N>::type;


// string
struct StrType
{
    static void serialize(PackStream& os, std::string& value)
    {
        WriteCompactSize(os, value.size());
        os.write(std::as_bytes(std::span{value}));
    }

    static void unserialize(PackStream& is, std::string& value)
    {
        auto size = ReadCompactSize(is);
        value.resize(size);
        is.read(std::as_writable_bytes(std::span{&value[0], size}));
    }
};

