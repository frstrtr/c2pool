#include <iostream>

struct version_param
{
    const int version;
};

constexpr static version_param A_ver {.version = 1};
constexpr static version_param B_ver {.version = 2};

struct Base 
{

};

struct A : public Base
{

};

struct B : public Base
{
    
};

template <version_param T>
void f()
{
    if constexpr (T.version == A_ver.version)
    {
        std::cout << "THIS A!" << std::endl;
    }
}

int main()
{
    constexpr auto v = []() { constexpr auto res = A_ver; return res; };
    f<B_ver>();
    f<v()>();
}