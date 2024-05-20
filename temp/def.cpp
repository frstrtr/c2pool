#include <iostream>

#define F \
    #define X std::cout << "hi" << std::endl;\
    X \
    #undef X

int main()
{
    F
}