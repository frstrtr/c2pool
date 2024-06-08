#include <iostream>
#include <string>
#include <type_traits>

enum Version
{
    v1 = 32,
    v2 = 33
};

struct Obj
{
    const Version version;

    int m_data;
    // std::enable_if_t<(N < 2), int> m_i;
    // std::enable_if_t<(N > 2), std::string> m_str;
    int m_i;
    std::string m_str;

    Obj(Version v, int data) : version(v), m_data(data) { }
};

void f(int VER)
{
    switch (VER)
    {
    case v1:
        
        break;
    case v2:
        break;
    default:
        break;
    }
}


// struct A : public Base
// {
//     A(int i) : Base(500), m_i(i) { }
// };

// struct B : public Base
// {
    

//     B(std::string str) : Base(1000), m_str(str) { }
// };

// template <typename T>
// void f(T* value)
// {
//     std::cout << value->m_data << " ";
//     if constexpr (T::)
// }

int main()
{
//    Base* a = new A(123);
//    Base* b = new B("asd");
    // Obj<1> obj1(100);
    // Obj<3> obj2(200);

    Obj obj1(v1, 322);
    Obj obj2(v2, 1337);



}