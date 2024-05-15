#include <iostream>
#include <variant>
#include <map>
#include <string>

#include <core/common.hpp>

int count = 0;

#define LIST_TYPES(N)   \
    X(T4##N) X(T5##N) X(T6##N) X(T7##N) X(T8##N) X(T9##N) X(T10##N) X(T11##N) X(T12##N) X(T13##N) X(T14##N) X(T15##N) X(T16##N)

#define MAKE_TYPES  \
    X(FIRST)    \
    X(SECOND)   \
    X(THIRD)    \
    LIST_TYPES(1)\
    LIST_TYPES(2)\
    LIST_TYPES(3)\
    LIST_TYPES(4)\
    LIST_TYPES(5)
    // X(T4) X(T5) X(T6) X(T7) X(T8) X(T9) X(T10) X(T11) X(T12) X(T13) X(T14) X(T15) X(T16)

#define X(NAMECLASS)   \
class NAMECLASS        \
{\
public:\
    void F_##NAMECLASS() const\
    {\
        count++;\
    }\
};
// std::cout << #NAMECLASS << std::endl;

MAKE_TYPES
#undef X

#define X(TYPE)\
    TYPE,

typedef std::variant<MAKE_TYPES int> types;
#undef X

struct CallTypeF {
    #define X(NAMETYPE) \
        void operator()(const NAMETYPE& value) { value.F_##NAMETYPE(); }
    
    MAKE_TYPES

    #undef X 
    void operator()(const int& value) { count -= 1;}
};

enum e_type
{
    #define X(NAMETYPE) E_##NAMETYPE,
        MAKE_TYPES
    #undef X
    LEN
};

// static const char* str_type[e_type::LEN] = 
// {
//     #define X(NAMETYPE) [E_##NAMETYPE] = #NAMETYPE
// };

std::map<std::string, e_type> str_type =
{
    #define X(name) {#name, e_type::E_##name},
    
    MAKE_TYPES
    #undef X
};

void make_type(types& result, std::string type_name)
{
    e_type t = str_type[type_name];
    switch (t)
    {
    #define X(name) case E_##name : result = name{}; return;
    MAKE_TYPES
    #undef X

    default:
        break;
    }
}

int main()
{
    std::string name;
    // std::cin >> name;
    name = "T65";
    CallTypeF* caller = new CallTypeF();
    auto begin = c2pool::debug_timestamp();
    for (int i = 0; i < 100'000; i++)
    {
        types a;
        make_type(a, name);
        std::visit(*caller, a);
    }
    auto finish = c2pool::debug_timestamp();

    std::cout << count << std::endl;
    std::cout << finish-begin << std::endl;
}