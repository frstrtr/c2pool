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

#include <core/legacy/packv1.hpp>
#include <core/legacy/pack_typesv1.hpp>

#define TEST(name)\
    void test_##name ()\
    {\
        std::cout << "###" << #name << "###\n";

#define END_TEST()\
        std::cout << std::endl;\
    }

TEST(INT)
    int32_t old_value = 322;

    PackStream stream;
    stream << old_value;
    // Serialize(stream, old_value);

    stream.print();
    int32_t new_value;
    stream >> new_value;
    // Unserialize(stream, new_value);

    std::cout << "Old value: " << old_value << std::endl;
    std::cout << "New value: " << new_value << std::endl;

    int64_t v1;
    try
    {
        stream >> v1;
        // Unserialize(stream, v1);
        std::cout << v1 << std::endl;
    } catch (const std::ios_base::failure& fail)
    {
        std::cout << fail.what() << std::endl;
    }
END_TEST()

TEST(STRING)
    PackStream stream;

    std::string str1("Hello world!");
    stream << str1;

    stream.print();

    std::string str2;
    stream >> str2;

    std::cout << "str2: [" << str2 << "]" << std::endl;
END_TEST()

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

    SERIALIZE_METHODS(custom) { READWRITE(obj.m_i, obj.m_str, obj.m_h); }
};

TEST(CUSTOM_TYPE)
    PackStream stream;
    
    custom value1(100, "hello c2pool", 300);
    value1.print();
    stream << value1;
    stream.print();

    custom value2;
    stream >> value2;
    value2.print();
END_TEST()

TEST(VECTOR)
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
END_TEST()


TEST(INT_TYPES)
    #define DEBUG_INT_TYPES(N) \
        PackStream  i_pack##N; i_pack##N << Using<IntType<N>>(i##N); \
        i_pack##N .print();\
        IntType<N>::num_type i_unpacked##N; i_pack##N >> i_unpacked##N ;\
        std::cout << i##N << " -> " << i_unpacked##N << std::endl; 
    
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
END_TEST()

TEST(INT_TYPES_BIG_ENDIAN)
    #define DEBUG_INT_TYPES(N) \
        PackStream  i_pack##N; i_pack##N << Using<IntType<N, true>>(i##N); \
        i_pack##N .print();\
        IntType<N, true>::num_type i_unpacked##N(0); i_pack##N >> Using<IntType<N, true>>(i_unpacked##N);\
        std::cout << i##N << " -> " << i_unpacked##N << std::endl; 
    
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
END_TEST()

enum test_enum
{
    i = 2,
    h = 4
};

TEST(ENUM)
    test_enum e1 = test_enum::h;

    PackStream stream;
    stream << Using<EnumType<IntType<16>>>(e1);

    stream.print();

    test_enum e2;
    stream >> Using<EnumType<IntType<16 >>>(e2);

    std::cout << e1 << " -> " << e2 << std::endl;
END_TEST()

TEST(FIXED_STR)
    // legacy::FixedStrType<5> legacy_str1("12345");
    // legacy::PackStream legacy_stream;
    // legacy_stream << legacy_str1;
    // std::cout << "legacy stream: " << legacy_stream << std::endl;

    std::string str1 = "123456";

    PackStream stream;
    stream << FixedString(str1, 6);
    stream.print();

    std::string str2;
    stream >> FixedString(str2, 6);
    std::cout << str1 << " -> " <<  str2 << std::endl;
END_TEST()

TEST(VAR_INT)
    #define DEBUG_INT_TYPES(N) \
        PackStream  i_pack##N; i_pack##N << VarInt(i##N); \
        i_pack##N .print();\
        uint64_t i_unpacked##N; i_pack##N >> VarInt(i_unpacked##N) ;\
        std::cout << (uint64_t)i##N << " -> " << i_unpacked##N << std::endl; 
    
    uint8_t     i8{250};
    DEBUG_INT_TYPES(8);

    uint16_t    i16{std::numeric_limits<uint16_t>::max()-1};
    DEBUG_INT_TYPES(16);
    
    uint32_t    i32{std::numeric_limits<uint32_t>::max()-1};
    DEBUG_INT_TYPES(32);
    
    uint64_t    i64{std::numeric_limits<uint64_t>::max()-1};
    DEBUG_INT_TYPES(64);

    #undef DEBUG_INT_TYPES
END_TEST()

TEST(ENUM_VAR_INT)
    test_enum e1 = test_enum::h;

    PackStream stream;
    stream << Using<EnumType<CompactFormat>>(e1);

    stream.print();

    test_enum e2;
    stream >> Using<EnumType<CompactFormat>>(e2);

    std::cout << e1 << " -> " << e2 << std::endl;
END_TEST()

struct DefaultUint32
{
    static uint32_t get() { return std::numeric_limits<uint32_t>::max(); }
};

TEST(OPTIONAL_TYPE)
    std::optional<uint32_t> num1;

    PackStream stream;
    stream << Using<OptionalType<DefaultUint32>>(num1);
    stream.print();
    
    std::optional<uint32_t> num2;
    stream >> Using<OptionalType<DefaultUint32>>(num2);
    std::cout << num2.value();
END_TEST()

struct DefaultCustom
{
    static custom get() { return custom{1, "hi", 16}; }
};

TEST(OPTIONAL_TYPE_FOR_CUSTOM)
    std::optional<custom> c1;

    PackStream stream;
    stream << Optional(c1, DefaultCustom);
    stream.print();
    
    std::optional<custom> c2;
    stream >> Optional(c2, DefaultCustom);
    c2->print();
END_TEST()

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

    SERIALIZE_METHODS(opt_custom) 
    { READWRITE(Optional(obj.m_c, DefaultCustom)); }
    // { formatter.action(stream, Using<OptionalType<DefaultCustom>>(obj.m_c)); }
    // { formatter.action(stream, *obj.m_c); }
};

TEST(OPTIONAL_FIELD)

    opt_custom v1;
    v1.print();

    PackStream stream;
    stream << v1;
    stream.print();

    opt_custom v2;
    stream >> v2;
    v2.print();

END_TEST()

TEST(OPTIONAL_FIELD2)

    opt_custom v1(1, "hello", 788);
    v1.print();

    PackStream stream;
    stream << v1;
    stream.print();

    opt_custom v2;
    stream >> v2;
    v2.print();

END_TEST()

int main()
{
    test_INT();
    test_STRING();
    test_CUSTOM_TYPE();
    test_VECTOR();
    test_INT_TYPES();
    test_INT_TYPES_BIG_ENDIAN();
    test_ENUM();
    test_FIXED_STR();
    test_VAR_INT();
    test_ENUM_VAR_INT();
    test_OPTIONAL_TYPE();
    test_OPTIONAL_TYPE_FOR_CUSTOM();
    test_OPTIONAL_FIELD();
    test_OPTIONAL_FIELD2();
}