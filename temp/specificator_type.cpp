/******************************************************************************

                              Online C++ Compiler.
               Code, Compile, Run and Debug C++ program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/

#include <iostream>

template <typename Child, bool BE>
struct A 
{
    static void print(const Child& v)
    {
        std::cout << "A: ";
        if constexpr (BE)
            std::cout << "[BE]";
        std::cout << v << std::endl;
    }
};

template <typename Child, bool BE>
struct B
{
    static void print(const Child& v)
    {
        std::cout << "B: ";
        if constexpr (BE)
            std::cout << "[BE]";
        std::cout << v << std::endl;
    }
};

template <int T, bool BE = false>
struct Base;

#define INT_TYPE_SPEC(N, PARENT_TYPE, CHILD_TYPE)\
    template<bool BE> struct Base<N, BE> : public PARENT_TYPE < CHILD_TYPE , BE > {};

INT_TYPE_SPEC(8, A, uint8_t);
INT_TYPE_SPEC(16, A, uint16_t);
INT_TYPE_SPEC(32, B, uint32_t);
INT_TYPE_SPEC(64, B, uint64_t);
#undef INT_TYPE_SPEC

// template<bool BE>
// struct Base<16, BE> : public A<uint16_t, BE> {};


int main()
{
    Base<32, true>::print(12312);

    return 0;
}
