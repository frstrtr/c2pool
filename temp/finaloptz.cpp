#include <iostream>
#include <string>
#include <variant>
#include <span>

#include <core/common.hpp>

struct A
{
    constexpr static int version = 32;
    int m_v;

    A(int i) : m_v(i) { }
};

struct B : public A
{
    constexpr static int version = 64;
    std::string m_str;

    B(std::string str) : A(1000), m_str(std::move(str)) { }
};

using ObjRef = std::variant<A, B>;

template <typename ObjType>
void f(ObjType& obj)
{
    if constexpr (ObjType::version >= 32)
    {
        obj.m_v += 10000;
    }
}

void apply_func(ObjRef& objRef)
{
    // Use std::visit with a lambda to eliminate the need for a separate struct
    std::visit([](auto& obj) { f(obj); }, objRef);
}

int main()
{
    ObjRef a = A{123};
    ObjRef b = B{"HELLO"};

    // Измените цикл оптимизации производительности
    const int iterations = 10'000'000;
    c2pool::debug_timestamp t1;
    for (int i = 0; i < iterations; ++i)
    {
        apply_func(a); 
    }
    c2pool::debug_timestamp t2;
    std::cout << std::get<A>(a).m_v << ": " << (t2-t1) << std::endl;
}