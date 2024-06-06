#include <iostream>

struct _Base {};

template <int VERSION>
struct Base : public _Base
{
    using version = std::integral_constant<int, VERSION>;
};

struct A : public Base<0>
{
    int i;

    A(int _i) : i(_i) {}
};

struct B : public Base<1>
{
    int b;

    B(int _b) : b(_b) {}
};

template <typename T>
int f(T&& v)
{
    static_assert(std::is_base_of<_Base, T>());
    if constexpr (std::is_same<typename T::version, A::version>::value)
        return v.i;
    if constexpr (std::is_same<typename T::version, B::version>::value)
        return v.b;
    return 0;
}

int main()
{
    int i;
    std::cin >> i;

    switch (i)
    {
    case 0:
        std::cout << f(A(111)) << std::endl;
        break;
    case 1:
        std::cout << f(B(50)) << std::endl;
    default:
        break;
    }
}