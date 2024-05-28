#include <iostream>
#include <span>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>
#include <string>

#include "packv2.hpp"
#include "pack_typesv2.hpp"

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
    IntType<32>::serialize(stream, old_value);

    stream.print();
    int32_t new_value;
    IntType<32>::unserialize(stream, new_value);

    std::cout << "Old value: " << old_value << std::endl;
    std::cout << "New value: " << new_value << std::endl;

    int64_t v1;
    try
    {
        IntType<64>::unserialize(stream, v1);
        std::cout << v1 << std::endl;
    } catch (const std::ios_base::failure& fail)
    {
        std::cout << fail.what() << std::endl;
    }
END_TEST()

TEST(STRING)
    PackStream stream;

    std::string str1("Hello world!");
    StrType::serialize(stream, str1);

    stream.print();

    std::string str2;
    StrType::unserialize(stream, str2);

    std::cout << "str2: [" << str2 << "]" << std::endl;
END_TEST()

struct custom
{
    int32_t m_i;
    std::string m_str;
    int64_t m_h;

    custom(int32_t i, std::string str, int64_t h) 
        : m_i(i), m_str(str), m_h(h)
    {

    }

    SERIALIZE_METHODS(custom, obj) { READWRITE(obj.m_i, obj.m_str, obj.m_sh); }

    // struct _custom : public PackType<custom>
    // {
    //     using i = IntType<32>;
    //     using str = StrType;
    //     using h = IntType<64>;

    //     static void serialize(PackStream& os, const custom& v)
    //     {
    //         os << i::serialize(v.i) << str::serialize(v.str) << h::serialize(v.str);
    //     }

    //     // static void unserialize(PackStream& os, custom& v)
    //     // {
    //     //     os >> i(v.i) >> str(v.str) >> h(v.h);
    //     // }
    // };
};

TEST(CUSTOM_TYPE)
    PackStream stream;

    custom value(100, "200", 300);
    stream << value;
    stream.print();
    
END_TEST()

int main()
{
    test_INT();
    test_STRING();
    test_CUSTOM_TYPE();
    return 0;
}