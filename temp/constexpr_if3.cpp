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
int f(T* _v)
{
    using type = std::remove_pointer_t<T>;
    static_assert(std::is_base_of<_Base, type>::value);
    
    if constexpr (std::is_same<typename type::version, A::version>())
    {
        auto v = static_cast<A*>(_v);
        return v->i;
    }
    
    if constexpr (std::is_same<typename type::version, B::version>::value)
    {
        auto v = static_cast<B*>(_v);
        return v->b;
    }
    return 0;
}

int main()
{
    int i;
    std::cin >> i;

    switch (i)
    {
    case 0:
    {
        Base<0>* a = new A(111);
        std::cout << f(a) << std::endl;
        break;
    }
    case 1:
    {
        Base<1>* b = new B(50);
        std::cout << f(b) << std::endl;
    }
    default:
        break;
    }
}