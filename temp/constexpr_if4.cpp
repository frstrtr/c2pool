#include <iostream>

struct _Base {};

template <typename SUB_TYPE, int VERSION>
struct Base : public _Base
{
    using version = std::integral_constant<int, VERSION>();
    using sub_type = SUB_TYPE;
};

struct A : public Base<A, 0>
{
    int i;

    A(int _i) : i(_i) {}
};

struct B : public Base<B, 1>
{
    int b;

    B(int _b) : b(_b) {}
};



template <typename T>
int f(_Base* _v)
{
    // using type = std::remove_pointer_t<T>;
    // static_assert(std::is_base_of<Base, T>::value);
    Base* v = static_cast<Base*>(_v);

    if constexpr (std::is_same<T::version, std::integral_constant<int, 1>>())
        return 1;

    return 0;
}

int main()
{
    int i;
    std::cin >> i;

    Base* value;

    switch (i)
    {
    case 0:
        value = new A(111);
        break;
    case 1:
        value = new B(50);
        break;
    default:
        break;
    }
    std::cout << f(value) << std::endl;
}