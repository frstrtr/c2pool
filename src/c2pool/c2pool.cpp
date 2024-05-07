#include <iostream>
#include <core/a.hpp>
// #include <core/a.hpp>
#include <nlohmann/json.hpp>
#include <btclibs/uint256.h>

int main(int argc, char *argv[])
{
    std::cout << "HI: " << a::f() << std::endl;
    std::cout << nlohmann::json::meta() << std::endl;
    std::cout << uint256S("ff").GetHex() << std::endl;
}