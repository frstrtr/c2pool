#include <iostream>
#include <map>
#include <functional>
#include <string>

#include <core/common.hpp>


struct message
{
    int data;

    message(int n) : data(n) {}
};

#define MAKE_LIST(N) X(1##N); X(2##N); X(3##N); X(4##N); X(5##N); X(6##N); X(7##N); X(8##N); X(9##N);

#define MAKE \
    MAKE_LIST(1); MAKE_LIST(2); MAKE_LIST(3); MAKE_LIST(4); MAKE_LIST(5); MAKE_LIST(6); MAKE_LIST(7); MAKE_LIST(8); MAKE_LIST(9);

#define X(N) \
    class MSG##N : public message { MSG##N() : message(N) {} };

MAKE
#undef X

int count = 0;

int main()
{
    std::map<std::string, std::function<void(message*)>> handlers;
    
    #define X(x) handlers[std::string("m") + std::string(#x)] = [&](auto* msg) { count += msg->data; delete msg; };
    MAKE
    #undef X

    std::string name;
    // std::cin >> name;
    name = "m65";

    auto begin = c2pool::debug_timestamp();
    for (int i = 0; i < 1'000'000; i++)
    {
        message* msg = new message(2);
        handlers[name](msg);
    }
    auto finish = c2pool::debug_timestamp();

    std::cout << count << std::endl;
    std::cout << finish-begin << std::endl;
    
}