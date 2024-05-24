#pragma once

#define MAKE_ARGS_EXPAND( x ) x
#define MAKE_ARGS_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, NAME,...) NAME

#define MAKE_ARGS_PASTE(...) MAKE_ARGS_EXPAND(MAKE_ARGS_GET_MACRO(__VA_ARGS__, \
        MAKE_ARGS_PASTE64, \
        MAKE_ARGS_PASTE63, \
        MAKE_ARGS_PASTE62, \
        MAKE_ARGS_PASTE61, \
        MAKE_ARGS_PASTE60, \
        MAKE_ARGS_PASTE59, \
        MAKE_ARGS_PASTE58, \
        MAKE_ARGS_PASTE57, \
        MAKE_ARGS_PASTE56, \
        MAKE_ARGS_PASTE55, \
        MAKE_ARGS_PASTE54, \
        MAKE_ARGS_PASTE53, \
        MAKE_ARGS_PASTE52, \
        MAKE_ARGS_PASTE51, \
        MAKE_ARGS_PASTE50, \
        MAKE_ARGS_PASTE49, \
        MAKE_ARGS_PASTE48, \
        MAKE_ARGS_PASTE47, \
        MAKE_ARGS_PASTE46, \
        MAKE_ARGS_PASTE45, \
        MAKE_ARGS_PASTE44, \
        MAKE_ARGS_PASTE43, \
        MAKE_ARGS_PASTE42, \
        MAKE_ARGS_PASTE41, \
        MAKE_ARGS_PASTE40, \
        MAKE_ARGS_PASTE39, \
        MAKE_ARGS_PASTE38, \
        MAKE_ARGS_PASTE37, \
        MAKE_ARGS_PASTE36, \
        MAKE_ARGS_PASTE35, \
        MAKE_ARGS_PASTE34, \
        MAKE_ARGS_PASTE33, \
        MAKE_ARGS_PASTE32, \
        MAKE_ARGS_PASTE31, \
        MAKE_ARGS_PASTE30, \
        MAKE_ARGS_PASTE29, \
        MAKE_ARGS_PASTE28, \
        MAKE_ARGS_PASTE27, \
        MAKE_ARGS_PASTE26, \
        MAKE_ARGS_PASTE25, \
        MAKE_ARGS_PASTE24, \
        MAKE_ARGS_PASTE23, \
        MAKE_ARGS_PASTE22, \
        MAKE_ARGS_PASTE21, \
        MAKE_ARGS_PASTE20, \
        MAKE_ARGS_PASTE19, \
        MAKE_ARGS_PASTE18, \
        MAKE_ARGS_PASTE17, \
        MAKE_ARGS_PASTE16, \
        MAKE_ARGS_PASTE15, \
        MAKE_ARGS_PASTE14, \
        MAKE_ARGS_PASTE13, \
        MAKE_ARGS_PASTE12, \
        MAKE_ARGS_PASTE11, \
        MAKE_ARGS_PASTE10, \
        MAKE_ARGS_PASTE9, \
        MAKE_ARGS_PASTE8, \
        MAKE_ARGS_PASTE7, \
        MAKE_ARGS_PASTE6, \
        MAKE_ARGS_PASTE5, \
        MAKE_ARGS_PASTE4, \
        MAKE_ARGS_PASTE3, \
        MAKE_ARGS_PASTE2, \
        MAKE_ARGS_PASTE1)(__VA_ARGS__))
#define MAKE_ARGS_PASTE2(func, v1) func(v1)
#define MAKE_ARGS_PASTE3(func, v1, v2) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE2(func, v2)
#define MAKE_ARGS_PASTE4(func, v1, v2, v3) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE3(func, v2, v3)
#define MAKE_ARGS_PASTE5(func, v1, v2, v3, v4) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE4(func, v2, v3, v4)
#define MAKE_ARGS_PASTE6(func, v1, v2, v3, v4, v5) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE5(func, v2, v3, v4, v5)
#define MAKE_ARGS_PASTE7(func, v1, v2, v3, v4, v5, v6) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE6(func, v2, v3, v4, v5, v6)
#define MAKE_ARGS_PASTE8(func, v1, v2, v3, v4, v5, v6, v7) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE7(func, v2, v3, v4, v5, v6, v7)
#define MAKE_ARGS_PASTE9(func, v1, v2, v3, v4, v5, v6, v7, v8) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE8(func, v2, v3, v4, v5, v6, v7, v8)
#define MAKE_ARGS_PASTE10(func, v1, v2, v3, v4, v5, v6, v7, v8, v9) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE9(func, v2, v3, v4, v5, v6, v7, v8, v9)
#define MAKE_ARGS_PASTE11(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE10(func, v2, v3, v4, v5, v6, v7, v8, v9, v10)
#define MAKE_ARGS_PASTE12(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE11(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11)
#define MAKE_ARGS_PASTE13(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE12(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12)
#define MAKE_ARGS_PASTE14(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE13(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13)
#define MAKE_ARGS_PASTE15(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE14(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14)
#define MAKE_ARGS_PASTE16(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE15(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)
#define MAKE_ARGS_PASTE17(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE16(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16)
#define MAKE_ARGS_PASTE18(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE17(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17)
#define MAKE_ARGS_PASTE19(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE18(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18)
#define MAKE_ARGS_PASTE20(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19) MAKE_ARGS_PASTE2(func, v1), MAKE_ARGS_PASTE19(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19)


///===========================
#define CAT(a_, b_) CAT_OO((a_, b_))
#define CAT_OO(par) CAT_I ## par 
#define CAT_I(a_, b_) a_ ## b_ 

#define SEQ_SIZE(seq) SEQ_SIZE_I(seq)
#define SEQ_SIZE_I(seq) CAT(SEQ_SIZE_, SEQ_SIZE_0 seq) 

#define SEQ_SIZE_0(_) SEQ_SIZE_1
#define SEQ_SIZE_1(_) SEQ_SIZE_2
#define SEQ_SIZE_2(_) SEQ_SIZE_3
#define SEQ_SIZE_3(_) SEQ_SIZE_4 
#define SEQ_SIZE_4(_) SEQ_SIZE_5 
#define SEQ_SIZE_5(_) SEQ_SIZE_6 
#define SEQ_SIZE_6(_) SEQ_SIZE_7 
#define SEQ_SIZE_7(_) SEQ_SIZE_8 

#define SEQ_SIZE_SEQ_SIZE_0 0
#define SEQ_SIZE_SEQ_SIZE_1 1
#define SEQ_SIZE_SEQ_SIZE_2 2
#define SEQ_SIZE_SEQ_SIZE_3 3
#define SEQ_SIZE_SEQ_SIZE_4 4
#define SEQ_SIZE_SEQ_SIZE_5 5
#define SEQ_SIZE_SEQ_SIZE_6 6
#define SEQ_SIZE_SEQ_SIZE_7 7


#define SEQ_ENUM(seq) SEQ_ENUM_I(SEQ_SIZE(seq), seq)
#define SEQ_ENUM_I(size, seq) CAT(SEQ_ENUM_, size) seq 

#define SEQ_ENUM_1(x) x
#define SEQ_ENUM_2(x) x, SEQ_ENUM_1
#define SEQ_ENUM_3(x) x, SEQ_ENUM_2
#define SEQ_ENUM_4(x) x, SEQ_ENUM_3
#define SEQ_ENUM_5(x) x, SEQ_ENUM_4
#define SEQ_ENUM_6(x) x, SEQ_ENUM_5
#define SEQ_ENUM_7(x) x, SEQ_ENUM_6
#define SEQ_ENUM_8(x) x, SEQ_ENUM_7