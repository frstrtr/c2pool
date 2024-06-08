#include <iostream>
#include <string>
#include <variant>
#include <span>

template <int VERSION>
struct ObjVer
{
    // constexpr static int version = VERSION;
    int m_i;

    ObjVer(int i) : m_i(i) {}
};

struct A : public ObjVer<32>
{
    constexpr static int version = 32;
    int m_v;

    A(int i) : ObjVer<32>(500), m_v(i) { }
};

struct B : public A
{
    constexpr static int version = 64;
    std::string m_str;

    B(std::string str) : A(1000), m_str(str) { }
};

struct C : public ObjVer<32>
{
    constexpr static int version = 31;
    int m_h;

    C(int h) : ObjVer<32>(500), m_h(h) { }
};

using ObjRef = std::variant<std::span<A>, std::span<B>>;

template <typename T>
void f(T& obj)
{
    using ObjType = typename T::value_type;
    std::cout << "f<" << ObjType::version << ">(" << typeid(ObjType).name() << "): ";
    std::cout << typeid(A).name() << ", " << typeid(B).name() << std::endl;
    if constexpr (ObjType::version >= 32)
    {
        obj.data()->m_v += 10000;
        std::cout << "A: " << obj.data()->m_v << std::endl;
    }
    if constexpr(std::is_same_v<ObjType, B>)
    {
        std::cout << obj.data()->m_str << std::endl;
    }
}

int main()
{
    std::span<A> __a;
    A* _a = new A{123};
    ObjRef a = std::span{_a,1};
    B* _b = new B{"HELLO"};
    ObjRef b = std::span{_b, 1};
    // ObjRef c = C{111};

    std::visit([](auto&& obj) { f(std::forward<decltype(obj)>(obj));} , a);
    std::visit([](auto&& obj) { f(std::forward<decltype(obj)>(obj));} , b);
    f(std::get<std::span<A>>(a));
    
    std::cout << sizeof(A) << "; " << sizeof(B) << "; " << sizeof(C) << "; " << sizeof(ObjRef) << std::endl;
}