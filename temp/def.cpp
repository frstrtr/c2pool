#include <iostream>
#include "def_macro.hpp"
#include "new_macro.hpp"

#define _MESSAGE_DATA_FIELD(first, second) std::cout << first + second << std::endl;
#define MESSAGE_DATA_FIELD(tup) _MESSAGE_DATA_FIELD tup

#define MESSAGE_FIELDS(...)\
    C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_FIELD, __VA_ARGS__))\

// ======================================================


// #define MAKE_ARGS_EXPAND( x ) x
// #define MAKE_ARGS_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, NAME,...) NAME
// #define MAKE_ARGS(...) MAKE_ARGS_EXPAND(MAKE_ARGS_GET_MACRO(MAKE_ARG1, MAKE_ARG2, MAKE_ARG3, MAKE_ARG4, __VA_ARGS__))

// #define MAKE_ARG1(x) x
// #define MAKE_ARG2(x) MAKE_ARG1, x
// #define MAKE_ARG3(x) MAKE_ARG2, x
// #define MAKE_ARG4(x) MAKE_ARG3, x
// #define MAKE_ARG5(x) MAKE_ARG4, x


#define _make_args(TYPE, NAME) TYPE _##NAME
#define make_args(X) _make_args X

    //inline void name(MAKE_ARGS_EXPAND(MAKE_ARGS_PASTE(make_args, __VA_ARGS__)))

#define MAKE_FUNC(name, ...)\
    inline void name(C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(ENUMERATE, make_args, __VA_ARGS__)))\
    {\
    \
    }\


#define test_f(a, b) a + b
#define test_def(x) test_f x

MAKE_FUNC(func1, (int, i), (int, h), (int, c))
MAKE_FUNC(func2, (int, i))

#define FUNC(name) _1_##name

#define _1_c func1
#define _1_f func2

int main()
{
    MESSAGE_FIELDS(
        (10, 5),
        (55, 7)
    )
    FUNC(c)(100, 20, 30);
    FUNC(f)(111);
    // std::cout << test_def((10, 5)) << std::endl;

}