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

    static constexpr int get_version() { return Base::m_version; }

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


template <typename T>
typename Version<T::version>::type f(Base* v)
{
    using type = Version<Base::get_version()>::type;
}

int main()
{

}