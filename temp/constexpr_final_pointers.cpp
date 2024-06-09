#include <iostream>
#include <string>
#include <variant>
#include <span>

#include <core/common.hpp>

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

using ObjRef = std::variant<A*, B*>;

template <typename...Args>
struct ObjsWrapper : std::variant<Args...>
{
    template<typename F>
    void call(F&& func)
    {
        std::visit(func, *this);
    }
};

#define CALL(func) call([](auto& obj) { func (obj); })

using ObjsRef = ObjsWrapper<A*, B*, C*>;

template <typename ObjType>
void f(ObjType* obj)
{
    // std::cout << "f<" << ObjType::version << ">(" << typeid(ObjType).name() << "): ";
    // std::cout << typeid(A).name() << ", " << typeid(B).name() << std::endl;
    if constexpr (ObjType::version >= 32)
    {
        obj->m_v += 10000;
        // std::cout << "A: " << obj->m_v << std::endl;
    }
    if constexpr(std::is_same_v<ObjType, B>)
    {
        // std::cout << obj->m_str << std::endl;
    }
}

int main()
{
    ObjRef a = new A{123};
    ObjRef b = new B{"HELLO"};
    // ObjRef c = C{111};

    std::visit([](auto&& obj) { f(obj);} , a);
    std::visit([](auto&& obj) { f(obj);} , b);
    f(std::get<A*>(a));
    
    std::cout << sizeof(A) << "; " << sizeof(B) << "; " << sizeof(C) << "; " << sizeof(ObjRef) << std::endl;
    
    std::cout << "=========" << std::endl;
    // ===================
    {
        A* _a = new A{123};
        c2pool::debug_timestamp t1;
        for (int i = 0; i < 20'000'001; i++)
            f(_a);
        
        c2pool::debug_timestamp t2;
        std::cout << _a->m_v << ": " << (t2-t1) << std::endl;
    }
    // ===================

    ObjsRef a2 {new A{123}};
    a2.call([](auto&& obj) {f(obj);});
    {
        c2pool::debug_timestamp t1;
        for (int i = 0; i < 10'000'000; i++)
            // std::visit([](auto& obj) { f(obj);} , a);
            a2.CALL(f);

        c2pool::debug_timestamp t2;
        std::cout << std::get<A*>(a)->m_v << ": " << (t2-t1) << std::endl;
    }
}