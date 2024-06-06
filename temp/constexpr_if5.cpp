#include <iostream>
#include <type_traits>

// Исходное определение структур.
struct Base
{
    const int m_version;

    constexpr Base(int version) : m_version{version} { }

    int get_version() const { return m_version; }

};

// Шаблонный класс, наследующийся от Base.
template <int VERSION>
struct BaseVersion : public Base
{
    BaseVersion() : Base(VERSION) {}
};

// Определяем структуры A и B, наследующиеся от соответствующих `BaseVersion`.
struct A : public BaseVersion<1>
{
    int i;
};

struct B : public BaseVersion<2>
{
    int h;
};

// Шаблон для работы с версиями.
template <int I>
struct Version
{
};

template <>
struct Version<1> { using type = A; };

template <>
struct Version<2> { using type = B; };

// Шаблонная функция f для приведения типов.
template <typename T>
typename Version<T::m_version>::type* f(Base* v)
{
    if (v->get_version() == T::m_version)
    {
        return static_cast<typename Version<T::m_version>::type*>(v);
    }
    return nullptr;
}

int main()
{
    A a;
    B b;

    Base* baseA = &a;
    Base* baseB = &b;

    auto resultA = f<A>(baseA);  // Должно вернуть указатель на A
    auto resultB = f<B>(baseB);  // Должно вернуть указатель на B

    if (resultA) std::cout << "A version is valid" << std::endl;
    if (resultB) std::cout << "B version is valid" << std::endl;

    return 0;
}