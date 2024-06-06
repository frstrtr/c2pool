#include <iostream>
#include <string>

struct Base
{
    const int m_version;

    constexpr Base(int version) : m_version{version} { }
};

constexpr Base A_VERSION{1};
constexpr Base B_VERSION{2};


constexpr int get_version(Base& b)
{
    return b.m_version;
}

template <Base b>
struct BaseVersion : public Base
{
    constexpr static Base _b = b;

    constexpr BaseVersion() : Base(b) { }
};

struct A : public BaseVersion<1>
{
    int m_i;

    A(int i) : m_i{i} { }
};

struct B : public BaseVersion<2>
{
    std::string m_h;

    B(std::string h) : m_h{h} { }
};

template <int I>
struct Version
{
};

template <>
struct Version<1> { using type = A; };

template <>
struct Version<2> { using type = B; };



typename Version<T::version>::type f(Base& v)
{

    // using type = Version<Base::get_version()>::type;
}

int main()
{
    auto _a = A(99);
    Base& a = _a;
    Base* b = new B("hello");

    f(a);
}