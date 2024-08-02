/******************************************************************************

                              Online C++ Compiler.
               Code, Compile, Run and Debug C++ program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/

#include <iostream>
#include <type_traits>

struct A
{
    int i;
    
    A() : i(100)
    {
        
    }
};

struct B
{
    double d;
    
    B() : d(10)
    {
        
    }
};

struct A_off {};
struct B_off {};

template <bool isA, bool isB>
struct Obj : std::conditional<isA, A, A_off>::type, std::conditional<isB, B, B_off>::type
{
        
};


enum ObjStates
{
    Server,
    Client
};

template<typename T>
concept IsComponent = std::is_same_v<A, T> || std::is_same_v<B, T>;

template <IsComponent...States>
struct ObjV2 : States...
{
};

int main()
{
    Obj<true, true> obj_all;
    std::cout << obj_all.i << " " << obj_all.d << std::endl;
    
    Obj<true, false> obj_a;
    std::cout << obj_a.i << " " << "" /*obj_a.d*/ << std::endl;
    
    Obj<false, true> obj_b;
    std::cout << /*obj_b.i*/ "" << " " << obj_b.d << std::endl;
    std::cout << "===========================================================" << std::endl;

    ObjV2<A, B> obj2_all;
    std::cout << obj2_all.i << " " << obj2_all.d << std::endl;

    ObjV2<A> obj2_a;
        std::cout << obj2_a.i << " " << "" /*obj2_a.d*/ << std::endl;

    ObjV2<B> obj2_b;
    std::cout << /*obj2_b.i*/ "" << " " << obj2_b.d << std::endl;

}

