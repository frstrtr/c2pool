#include <gtest/gtest.h>

#include <iostream>
#include <span>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>
#include <string>
#include <optional>

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/opscript.hpp>

#include <core/legacy/packv1.hpp>
// #include <core/legacy/pack_typesv1.hpp>

TEST(Pack, INT)
{
    int32_t old_value = 322;

    PackStream stream;
    stream << old_value;
    stream.print();

    int32_t new_value;
    stream >> new_value;
    ASSERT_EQ(old_value, new_value);

    std::cout << "Old value: " << old_value << std::endl;
    std::cout << "New value: " << new_value << std::endl;

    int64_t v1;
    ASSERT_THROW({ stream >> v1; }, std::ios_base::failure);
}

TEST(Pack, STRING)
{
    PackStream stream;

    std::string str1("Hello world!");
    stream << str1;

    stream.print();

    std::string str2;
    stream >> str2;

    std::cout << "str2: [" << str2 << "]" << std::endl;
    ASSERT_EQ(str1, str2);
}

struct custom
{
    int32_t m_i;
    std::string m_str;
    int64_t m_h;

    custom() {}

    custom(int32_t i, std::string str, int64_t h) 
        : m_i(i), m_str(str), m_h(h)
    {

    }

    void print() const
    {
        std::cout << m_i << " <" << m_str << "> " << m_h << std::endl;
    }

    bool operator==(const custom& c) const
    {
        return std::make_tuple(m_i, m_str, m_h) == std::make_tuple(c.m_i, c.m_str, c.m_h);
    }

    bool operator!=(const custom& c)
    {
        return !(*this == c);
    }

    SERIALIZE_METHODS(custom) { READWRITE(obj.m_i, obj.m_str, obj.m_h); }
};

TEST(Pack, CUSTOM_TYPE)
{
    PackStream stream;
    
    custom value1(100, "hello c2pool", 300);
    value1.print();
    stream << value1;
    stream.print();

    custom value2;
    stream >> value2;
    value2.print();

    ASSERT_EQ(value1, value2);
}

TEST(Pack, VECTOR)
{
    PackStream stream;

    std::vector<uint32_t> nums1 {1, 22, 30, 55, 888};
    for (const auto& n : nums1) std::cout << n << " ";
    std::cout << std::endl;
    stream << nums1;
    stream.print();

    std::vector<uint32_t> nums2;
    stream >> nums2;
    for (const auto& n : nums2) std::cout << n << " ";
    std::cout << std::endl;
    stream.print();

    ASSERT_EQ(nums1, nums2);
}


TEST(Pack, INT_TYPES)
{
    #define DEBUG_INT_TYPES(N) \
        PackStream  i_pack##N; i_pack##N << Using<IntType<N>>(i##N); \
        i_pack##N .print();\
        IntType<N>::num_type i_unpacked##N; i_pack##N >> i_unpacked##N ;\
        std::cout << i##N << " -> " << i_unpacked##N << std::endl;\
        ASSERT_EQ(i##N , i_unpacked##N);
    
    uint8_t     i8{std::numeric_limits<uint8_t>::max()};
    DEBUG_INT_TYPES(8);

    uint16_t    i16{std::numeric_limits<uint16_t>::max()};
    DEBUG_INT_TYPES(16);
    
    uint32_t    i32{std::numeric_limits<uint32_t>::max()};
    DEBUG_INT_TYPES(32);
    
    uint64_t    i64{std::numeric_limits<uint64_t>::max()};
    DEBUG_INT_TYPES(64);

    uint128     i128{"ffffffffffffffffffffffffffffffff"};
    DEBUG_INT_TYPES(128);

    uint160     i160{"ffffffffffffffffffffffffffffffffffffffff"};
    DEBUG_INT_TYPES(160);
    
    uint256     i256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    DEBUG_INT_TYPES(256);
    
    uint288     i288{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    DEBUG_INT_TYPES(288);

#undef DEBUG_INT_TYPES
}

TEST(Pack, INT_TYPES_BIG_ENDIAN)
{
    #define DEBUG_INT_TYPES(N) \
        PackStream  i_pack##N; i_pack##N << Using<IntType<N, true>>(i##N); \
        i_pack##N .print();\
        IntType<N, true>::num_type i_unpacked##N(0); i_pack##N >> Using<IntType<N, true>>(i_unpacked##N);\
        std::cout << i##N << " -> " << i_unpacked##N << std::endl;\
        ASSERT_EQ(i##N , i_unpacked##N);
    
    uint8_t     i8{2};
    DEBUG_INT_TYPES(8);

    uint16_t    i16{2};
    DEBUG_INT_TYPES(16);
    
    uint32_t    i32{2};
    DEBUG_INT_TYPES(32);
    
    uint64_t    i64{2};
    DEBUG_INT_TYPES(64);

    uint128     i128{2};
    DEBUG_INT_TYPES(128);

    uint160     i160{2};
    DEBUG_INT_TYPES(160);
    
    uint256     i256{2};
    DEBUG_INT_TYPES(256);
    
    uint288     i288{2};
    DEBUG_INT_TYPES(288);

#undef DEBUG_INT_TYPES
}

enum test_enum
{
    i = 2,
    h = 4
};

TEST(Pack, ENUM)
{
    test_enum e1 = test_enum::h;

    PackStream stream;
    stream << Using<EnumType<IntType<16>>>(e1);

    stream.print();

    test_enum e2;
    stream >> Using<EnumType<IntType<16 >>>(e2);

    std::cout << e1 << " -> " << e2 << std::endl;
    ASSERT_EQ(e1, e2);
}

TEST(Pack, FIXED_STR)
{
    // legacy::FixedStrType<5> legacy_str1("12345");
    // legacy::PackStream legacy_stream;
    // legacy_stream << legacy_str1;
    // std::cout << "legacy stream: " << legacy_stream << std::endl;

    FixedStrType<6> str1("123456");

    PackStream stream;
    stream << str1;
    stream.print();

    FixedStrType<6> str2;
    stream >> str2;
    std::cout << str1.ToString() << " -> " <<  str2.ToString() << std::endl;
    ASSERT_EQ(str1.ToString(), str2.ToString());
}

TEST(Pack, VAR_INT)
{
    #define DEBUG_INT_TYPES(N) \
        PackStream  i_pack##N; i_pack##N << VarInt(i##N); \
        i_pack##N .print();\
        uint64_t i_unpacked##N; i_pack##N >> VarInt(i_unpacked##N) ;\
        std::cout << (uint64_t)i##N << " -> " << i_unpacked##N << std::endl;\
        ASSERT_EQ(i##N , i_unpacked##N);
    
    uint8_t     i8{250};
    DEBUG_INT_TYPES(8);

    uint16_t    i16{std::numeric_limits<uint16_t>::max()-1};
    DEBUG_INT_TYPES(16);
    
    uint32_t    i32{std::numeric_limits<uint32_t>::max()-1};
    DEBUG_INT_TYPES(32);
    
    uint64_t    i64{std::numeric_limits<uint64_t>::max()-1};
    DEBUG_INT_TYPES(64);

    #undef DEBUG_INT_TYPES
}

TEST(Pack, ENUM_VAR_INT)
{
    test_enum e1 = test_enum::h;

    PackStream stream;
    stream << Using<EnumType<CompactFormat>>(e1);

    stream.print();

    test_enum e2;
    stream >> Using<EnumType<CompactFormat>>(e2);

    std::cout << e1 << " -> " << e2 << std::endl;
    ASSERT_EQ(e1, e2);
}

struct DefaultUint32
{
    static uint32_t get() { return std::numeric_limits<uint32_t>::max(); }
};

TEST(Pack, OPTIONAL_TYPE)
{
    std::optional<uint32_t> num1;

    PackStream stream;
    stream << Using<OptionalType<DefaultUint32>>(num1);
    stream.print();
    
    std::optional<uint32_t> num2;
    stream >> Using<OptionalType<DefaultUint32>>(num2);
    std::cout << num2.value();
    ASSERT_EQ(DefaultUint32::get(), num2.value());
}

struct DefaultCustom
{
    static custom get() { return custom{1, "hi", 16}; }
};

TEST(Pack, OPTIONAL_TYPE_FOR_CUSTOM)
{
    std::optional<custom> c1;

    PackStream stream;
    stream << Optional(c1, DefaultCustom);
    stream.print();
    
    std::optional<custom> c2;
    stream >> Optional(c2, DefaultCustom);
    c2->print();

    ASSERT_EQ(DefaultCustom::get(), c2.value());
}

struct opt_custom
{
    std::optional<custom> m_c;

    opt_custom() {}

    opt_custom(int32_t i, std::string str, int64_t h) 
        : m_c(std::make_optional<custom>(i, str, h))
    {

    }

    void print() const
    {
        if (m_c)
            m_c->print();
        else
            std::cout << "opt_custom is none!" << std::endl;
    }

    bool operator==(const opt_custom& c) const
    {
        return std::make_tuple(m_c.has_value(), m_c.value_or(custom{})) == std::make_tuple(c.m_c.has_value(), c.m_c.value_or(custom{}));
    }

    bool operator!=(const opt_custom& c)
    {
        return !(*this == c);
    }

    SERIALIZE_METHODS(opt_custom) 
    { READWRITE(Optional(obj.m_c, DefaultCustom)); }
    // { formatter.action(stream, Using<OptionalType<DefaultCustom>>(obj.m_c)); }
    // { formatter.action(stream, *obj.m_c); }
};

TEST(Pack, OPTIONAL_FIELD)
{
    opt_custom v1;
    v1.print();

    PackStream stream;
    stream << v1;
    stream.print();

    opt_custom v2;
    stream >> v2;
    v2.print();
    ASSERT_EQ(DefaultCustom::get(), v2.m_c);
}

TEST(Pack, OPTIONAL_FIELD2)
{
    opt_custom v1(1, "hello", 788);
    v1.print();

    PackStream stream;
    stream << v1;
    stream.print();

    opt_custom v2;
    stream >> v2;
    v2.print();
    ASSERT_EQ(v1, v2);
}

TEST(Pack, UINT_CHECK1)
{    
    uint256 n1;

    PackStream stream;
    stream << n1;
    stream.print();

    uint256 n2;
    stream >> n2;

    std::cout << n1 << " -> " << n2 << std::endl;
    ASSERT_EQ(n1, n2);
}

TEST(Pack, UINT_CHECK2)
{
    uint256 n1; n1.SetNull();

    PackStream stream;
    stream << n1;
    stream.print();

    uint256 n2;
    stream >> n2;

    std::cout << n1 << " -> " << n2 << std::endl;
    ASSERT_EQ(n1, n2);
}

TEST(Pack, OP_SCRIPT)
{
    std::vector<unsigned char> vch{'a', 'c', 'o'};
    OPScript script(vch.begin(), vch.end());

    PackStream stream;
    stream << script;

    std::for_each(script.m_data.begin(), script.m_data.end(), [&](const auto& ch) { std::cout << ch << " "; });
    std::cout << std::endl;
    stream.print();

    OPScript script2;
    stream >> script2;
    std::for_each(script.m_data.begin(), script.m_data.end(), [&](const auto& ch) { std::cout << ch << " "; });
    std::cout << std::endl;

    ASSERT_EQ(script, script2);
    ASSERT_TRUE(script.m_data == vch && script2.m_data == vch);
}