#pragma once

#include <nlohmann/json.hpp>

#define CUSTOM_METRIC_EXPAND( x ) x
#define CUSTOM_METRIC_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, NAME,...) NAME
#define CUSTOM_METRIC_PASTE(...) CUSTOM_METRIC_EXPAND(CUSTOM_METRIC_GET_MACRO(__VA_ARGS__, \
        CUSTOM_METRIC_PASTE64, \
        CUSTOM_METRIC_PASTE63, \
        CUSTOM_METRIC_PASTE62, \
        CUSTOM_METRIC_PASTE61, \
        CUSTOM_METRIC_PASTE60, \
        CUSTOM_METRIC_PASTE59, \
        CUSTOM_METRIC_PASTE58, \
        CUSTOM_METRIC_PASTE57, \
        CUSTOM_METRIC_PASTE56, \
        CUSTOM_METRIC_PASTE55, \
        CUSTOM_METRIC_PASTE54, \
        CUSTOM_METRIC_PASTE53, \
        CUSTOM_METRIC_PASTE52, \
        CUSTOM_METRIC_PASTE51, \
        CUSTOM_METRIC_PASTE50, \
        CUSTOM_METRIC_PASTE49, \
        CUSTOM_METRIC_PASTE48, \
        CUSTOM_METRIC_PASTE47, \
        CUSTOM_METRIC_PASTE46, \
        CUSTOM_METRIC_PASTE45, \
        CUSTOM_METRIC_PASTE44, \
        CUSTOM_METRIC_PASTE43, \
        CUSTOM_METRIC_PASTE42, \
        CUSTOM_METRIC_PASTE41, \
        CUSTOM_METRIC_PASTE40, \
        CUSTOM_METRIC_PASTE39, \
        CUSTOM_METRIC_PASTE38, \
        CUSTOM_METRIC_PASTE37, \
        CUSTOM_METRIC_PASTE36, \
        CUSTOM_METRIC_PASTE35, \
        CUSTOM_METRIC_PASTE34, \
        CUSTOM_METRIC_PASTE33, \
        CUSTOM_METRIC_PASTE32, \
        CUSTOM_METRIC_PASTE31, \
        CUSTOM_METRIC_PASTE30, \
        CUSTOM_METRIC_PASTE29, \
        CUSTOM_METRIC_PASTE28, \
        CUSTOM_METRIC_PASTE27, \
        CUSTOM_METRIC_PASTE26, \
        CUSTOM_METRIC_PASTE25, \
        CUSTOM_METRIC_PASTE24, \
        CUSTOM_METRIC_PASTE23, \
        CUSTOM_METRIC_PASTE22, \
        CUSTOM_METRIC_PASTE21, \
        CUSTOM_METRIC_PASTE20, \
        CUSTOM_METRIC_PASTE19, \
        CUSTOM_METRIC_PASTE18, \
        CUSTOM_METRIC_PASTE17, \
        CUSTOM_METRIC_PASTE16, \
        CUSTOM_METRIC_PASTE15, \
        CUSTOM_METRIC_PASTE14, \
        CUSTOM_METRIC_PASTE13, \
        CUSTOM_METRIC_PASTE12, \
        CUSTOM_METRIC_PASTE11, \
        CUSTOM_METRIC_PASTE10, \
        CUSTOM_METRIC_PASTE9, \
        CUSTOM_METRIC_PASTE8, \
        CUSTOM_METRIC_PASTE7, \
        CUSTOM_METRIC_PASTE6, \
        CUSTOM_METRIC_PASTE5, \
        CUSTOM_METRIC_PASTE4, \
        CUSTOM_METRIC_PASTE3, \
        CUSTOM_METRIC_PASTE2, \
        CUSTOM_METRIC_PASTE1)(__VA_ARGS__))
#define CUSTOM_METRIC_PASTE2(func, v1) func(v1)
#define CUSTOM_METRIC_PASTE3(func, v1, v2) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE2(func, v2)
#define CUSTOM_METRIC_PASTE4(func, v1, v2, v3) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE3(func, v2, v3)
#define CUSTOM_METRIC_PASTE5(func, v1, v2, v3, v4) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE4(func, v2, v3, v4)
#define CUSTOM_METRIC_PASTE6(func, v1, v2, v3, v4, v5) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE5(func, v2, v3, v4, v5)
#define CUSTOM_METRIC_PASTE7(func, v1, v2, v3, v4, v5, v6) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE6(func, v2, v3, v4, v5, v6)
#define CUSTOM_METRIC_PASTE8(func, v1, v2, v3, v4, v5, v6, v7) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE7(func, v2, v3, v4, v5, v6, v7)
#define CUSTOM_METRIC_PASTE9(func, v1, v2, v3, v4, v5, v6, v7, v8) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE8(func, v2, v3, v4, v5, v6, v7, v8)
#define CUSTOM_METRIC_PASTE10(func, v1, v2, v3, v4, v5, v6, v7, v8, v9) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE9(func, v2, v3, v4, v5, v6, v7, v8, v9)
#define CUSTOM_METRIC_PASTE11(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE10(func, v2, v3, v4, v5, v6, v7, v8, v9, v10)
#define CUSTOM_METRIC_PASTE12(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE11(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11)
#define CUSTOM_METRIC_PASTE13(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE12(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12)
#define CUSTOM_METRIC_PASTE14(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE13(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13)
#define CUSTOM_METRIC_PASTE15(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE14(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14)
#define CUSTOM_METRIC_PASTE16(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE15(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)
#define CUSTOM_METRIC_PASTE17(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE16(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16)
#define CUSTOM_METRIC_PASTE18(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE17(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17)
#define CUSTOM_METRIC_PASTE19(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE18(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18)
#define CUSTOM_METRIC_PASTE20(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19) CUSTOM_METRIC_PASTE2(func, v1) CUSTOM_METRIC_PASTE19(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19)

#define CUSTOM_METRIC_FIELD_ADD(field_name) l.field_name += r.field_name;
#define CUSTOM_METRIC_FIELD_SUB(field_name) l.field_name -= r.field_name;

#define CUSTOM_METRIC_DEFINE_TYPE_INTRUSIVE(Type, ...) \
    friend Type& operator -=(Type& l, const Type& r) { \
        CUSTOM_METRIC_EXPAND(CUSTOM_METRIC_PASTE(CUSTOM_METRIC_FIELD_SUB, __VA_ARGS__)) \
        return l;                                                                       \
    }                                                  \
    \
    friend Type& operator +=(Type& l, const Type& r) { \
        CUSTOM_METRIC_EXPAND(CUSTOM_METRIC_PASTE(CUSTOM_METRIC_FIELD_ADD, __VA_ARGS__)) \
        return l;                                                                       \
    }                                                  \
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Type, __VA_ARGS__)

