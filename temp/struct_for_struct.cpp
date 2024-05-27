#include <iostream>

template <typename T>
struct Base
{
    void print(const T& value)
    {
        value.print();
    }
};

struct A
{
    struct a : public Base<a>
    {
        int m_i;

        a(int i) : m_i(i) {}

        void print() const
        {
            std::cout << m_i << std::endl;
        }
    };

    a m_value;
    A(int value) : m_value(value) {}
};


int main()
{
    A value{100};
    value.m_value.print();
}