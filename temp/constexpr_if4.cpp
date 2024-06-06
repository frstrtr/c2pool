#include <iostream>


// struct Base
// {
//     const int version;
// };

// struct Base2 : public Base
// {

// };

// constexpr static Base2 A {Base::version = 1};

struct Base
{
    const int m_version;

    constexpr Base(int version) : m_version{version} { }
};

template <int VERSION>
struct BaseVersion : public Base
{
    BaseVersion() : Base(VERSION) {}
};

struct A : public BaseVersion<1>
{
    int i;
};

struct B : public BaseVersion<2>
{
    int h;
};

template <int I>
struct Version
{
};

template <>
struct Version<1> { using type = A; };

template <>
struct Version<2> { using type = B; };

// template <typename From, typename To>
// constexpr To* f(From* v) 
// { 
//     return (To*) v; 
// }

template <typename T>
typename Version<T::version>::type f(Base* v)
{
    using type = Version<Base::m_version>;
}

int main()
{


    // uint64_t* v = new uint64_t; std::cin >> *v;
    // auto v2 = f<uint64_t, uint32_t>(v);

    // std::cout << *v2 << std::endl;

    // Base* value;

    // switch (i)
    // {
    // case 0:
    //     value = new A(111);
    //     break;
    // case 1:
    //     value = new B(50);
    //     break;
    // default:
    //     break;
    // }
    // std::cout << f(value) << std::endl;
}