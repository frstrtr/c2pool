#include <iostream>
#include <string>


struct Base
{
    int m_data;

    Base(int data) : m_data(data) { }
};

struct A : public Base
{
    int m_i;

    A(int i) : Base(500), m_i(i) { }
};

struct B : public Base
{
    std::string m_str;

    B(std::string str) : Base(1000), m_str(str) { }
};

struct Wrapper
{
    
};

template <typename T>
void f(T* value)
{
    std::cout << value->m_data << " ";
    if constexpr (T::)
}

int main()
{
   Base* a = new A(123);
   Base* b = new B("asd");


}