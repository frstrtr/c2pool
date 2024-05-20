#include <iostream>

#define MAKE_MAP(...) f(__VA_ARGS__)

template<typename... Args>
void f(std::string)
{
    
}

int main()
{
    MAKE_MAP(1000, 5000, 12313);
}