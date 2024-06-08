#include <iostream>
#include <string>
#include <variant>

template <int VERSION>
struct ObjVer
{
    constexpr static int version = VERSION;
    int m_i;

    ObjVer(int i) : m_i(i) {}
};

struct A : public ObjVer<32>
{
    int m_v;

    A(int i) : ObjVer<32>(500), m_v(i) { }
};

struct B : public ObjVer<64>
{
    std::string m_str;

    B(std::string str) : ObjVer(1000), m_str(str) { }
};

using ObjRef = std::variant<A, B>;

template <typename ObjType>
void f(ObjType& obj)
{
    std::cout << "f(" << typeid(ObjType).name() << "): ";
    std::cout << typeid(A).name() << ", " << typeid(B).name() << std::endl;
    if constexpr(std::is_base_of<ObjVer<32>, ObjType>::value)
    {
        obj.m_v += 10000;
        std::cout << "A: " << obj.m_v << std::endl;
    }
    if constexpr(std::is_same_v<ObjType, B>)
    {
        std::cout << obj.m_str << std::endl;
    }
}

int main()
{
    ObjRef a = A{123};
    ObjRef b = B{"HELLO"};

    std::visit([](auto&& obj) { f(std::forward<decltype(obj)>(obj));} , a);
    std::visit([](auto&& obj) { f(std::forward<decltype(obj)>(obj));} , b);
    f(std::get<A>(a));
    
    std::cout << sizeof(A) << "; " << sizeof(B) << "; " << sizeof(ObjRef) << std::endl;
}