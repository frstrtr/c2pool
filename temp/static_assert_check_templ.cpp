#include <iostream>
#include <variant>

template <int I>
struct Base
{
    constexpr static int i = I;
};

struct A : public Base<2>
{
    int m_num;

    A() {}
    A(int num) : m_num(num) {}
};


struct B : public Base<4>
{
    float m_fl;

    B() {}
    B(float fl) : m_fl(fl) {}
};


struct FakeBase
{
    int i = -100;
};

template <typename T>
concept is_not_fake = std::is_base_of<Base<T::i>, T>::value;

template <typename...T>
struct Variant : std::variant<T...>
{
    static_assert((is_not_fake<T> && ...), "fake");
};

template <typename T>
void f(T& value)
{
    std::cout << value.i << std::endl;

    if constexpr (std::is_same<A, T>())
        std::cout << value.m_num << std::endl;
    if constexpr (std::is_same<B, T>())
        std::cout << value.m_fl << std::endl;
}


int main()
{

    Variant<B, A> var {A{109}};
    std::visit([](auto&& v) { f(v); }, var);

    Variant<B, A, FakeBase> fake {FakeBase{}};
    std::visit([](auto&& v) { f(v); }, fake);
}