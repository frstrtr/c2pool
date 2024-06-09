#include <iostream>

template <int V>
struct Spec {};

struct A
{
    

    template <>
    struct ::Spec { using type = A; };
};

int main()
{

}