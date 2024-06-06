#include <iostream>

struct A1
{
    int i;
    int h;
};

struct A2 : public A1
{
    std::string str;
};

template <typename A>
inline void f(A&& a)
{
    std::cout << a.i << " " << a.h << " ";
    if constexpr (std::is_same<A, A2>())
        std::cout << a.str << std::endl;
    std::cout << std::endl;
}

int main()
{
    int i;
    std::cin >> i;

    switch (i)
    {
    case 0:
        f(A1{100, 50});
        break;
    case 1:
        f(A2{100, 50, "this A2!"});
    default:
        break;
    }
}