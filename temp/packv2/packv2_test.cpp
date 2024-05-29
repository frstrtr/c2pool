#include <iostream>
#include <span>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>
#include <string>

#include "pack.hpp"

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
        std::cout << m_i << " " << m_str << " " << m_h << std::endl;
    }

    SERIALIZE_METHODS(custom) { READWRITE(obj.m_i, obj.m_str, obj.m_h); }
};

TEST(CUSTOM_TYPE)
    PackStream stream;
    
    custom value1(100, "200", 300);
    value1.print();
    stream << value1;
    stream.print();

    custom value2;
    stream >> value2;
    value2.print();
END_TEST()

int main()
{
    test_INT();
    test_STRING();
    test_CUSTOM_TYPE();
    
    return 0;
}