#pragma once

#define MESSAGE_DATA_EXPAND( x ) x
#define MESSAGE_DATA_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, NAME,...) NAME

#define MESSAGE_DATA_PASTE(...) MESSAGE_DATA_EXPAND(MESSAGE_DATA_GET_MACRO(__VA_ARGS__, \
        MESSAGE_DATA_PASTE64, \
        MESSAGE_DATA_PASTE63, \
        MESSAGE_DATA_PASTE62, \
        MESSAGE_DATA_PASTE61, \
        MESSAGE_DATA_PASTE60, \
        MESSAGE_DATA_PASTE59, \
        MESSAGE_DATA_PASTE58, \
        MESSAGE_DATA_PASTE57, \
        MESSAGE_DATA_PASTE56, \
        MESSAGE_DATA_PASTE55, \
        MESSAGE_DATA_PASTE54, \
        MESSAGE_DATA_PASTE53, \
        MESSAGE_DATA_PASTE52, \
        MESSAGE_DATA_PASTE51, \
        MESSAGE_DATA_PASTE50, \
        MESSAGE_DATA_PASTE49, \
        MESSAGE_DATA_PASTE48, \
        MESSAGE_DATA_PASTE47, \
        MESSAGE_DATA_PASTE46, \
        MESSAGE_DATA_PASTE45, \
        MESSAGE_DATA_PASTE44, \
        MESSAGE_DATA_PASTE43, \
        MESSAGE_DATA_PASTE42, \
        MESSAGE_DATA_PASTE41, \
        MESSAGE_DATA_PASTE40, \
        MESSAGE_DATA_PASTE39, \
        MESSAGE_DATA_PASTE38, \
        MESSAGE_DATA_PASTE37, \
        MESSAGE_DATA_PASTE36, \
        MESSAGE_DATA_PASTE35, \
        MESSAGE_DATA_PASTE34, \
        MESSAGE_DATA_PASTE33, \
        MESSAGE_DATA_PASTE32, \
        MESSAGE_DATA_PASTE31, \
        MESSAGE_DATA_PASTE30, \
        MESSAGE_DATA_PASTE29, \
        MESSAGE_DATA_PASTE28, \
        MESSAGE_DATA_PASTE27, \
        MESSAGE_DATA_PASTE26, \
        MESSAGE_DATA_PASTE25, \
        MESSAGE_DATA_PASTE24, \
        MESSAGE_DATA_PASTE23, \
        MESSAGE_DATA_PASTE22, \
        MESSAGE_DATA_PASTE21, \
        MESSAGE_DATA_PASTE20, \
        MESSAGE_DATA_PASTE19, \
        MESSAGE_DATA_PASTE18, \
        MESSAGE_DATA_PASTE17, \
        MESSAGE_DATA_PASTE16, \
        MESSAGE_DATA_PASTE15, \
        MESSAGE_DATA_PASTE14, \
        MESSAGE_DATA_PASTE13, \
        MESSAGE_DATA_PASTE12, \
        MESSAGE_DATA_PASTE11, \
        MESSAGE_DATA_PASTE10, \
        MESSAGE_DATA_PASTE9, \
        MESSAGE_DATA_PASTE8, \
        MESSAGE_DATA_PASTE7, \
        MESSAGE_DATA_PASTE6, \
        MESSAGE_DATA_PASTE5, \
        MESSAGE_DATA_PASTE4, \
        MESSAGE_DATA_PASTE3, \
        MESSAGE_DATA_PASTE2, \
        MESSAGE_DATA_PASTE1)(__VA_ARGS__))
#define MESSAGE_DATA_PASTE2(func, v1) func(v1)
#define MESSAGE_DATA_PASTE3(func, v1, v2) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE2(func, v2)
#define MESSAGE_DATA_PASTE4(func, v1, v2, v3) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE3(func, v2, v3)
#define MESSAGE_DATA_PASTE5(func, v1, v2, v3, v4) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE4(func, v2, v3, v4)
#define MESSAGE_DATA_PASTE6(func, v1, v2, v3, v4, v5) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE5(func, v2, v3, v4, v5)
#define MESSAGE_DATA_PASTE7(func, v1, v2, v3, v4, v5, v6) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE6(func, v2, v3, v4, v5, v6)
#define MESSAGE_DATA_PASTE8(func, v1, v2, v3, v4, v5, v6, v7) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE7(func, v2, v3, v4, v5, v6, v7)
#define MESSAGE_DATA_PASTE9(func, v1, v2, v3, v4, v5, v6, v7, v8) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE8(func, v2, v3, v4, v5, v6, v7, v8)
#define MESSAGE_DATA_PASTE10(func, v1, v2, v3, v4, v5, v6, v7, v8, v9) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE9(func, v2, v3, v4, v5, v6, v7, v8, v9)
#define MESSAGE_DATA_PASTE11(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE10(func, v2, v3, v4, v5, v6, v7, v8, v9, v10)
#define MESSAGE_DATA_PASTE12(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE11(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11)
#define MESSAGE_DATA_PASTE13(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE12(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12)
#define MESSAGE_DATA_PASTE14(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE13(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13)
#define MESSAGE_DATA_PASTE15(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE14(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14)
#define MESSAGE_DATA_PASTE16(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE15(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)
#define MESSAGE_DATA_PASTE17(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE16(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16)
#define MESSAGE_DATA_PASTE18(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE17(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17)
#define MESSAGE_DATA_PASTE19(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE18(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18)
#define MESSAGE_DATA_PASTE20(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19) MESSAGE_DATA_PASTE2(func, v1) MESSAGE_DATA_PASTE19(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19)

#define _MESSAGE_DATA_FIELD(pack_type, field_name) pack_type::get_type field_name;
#define MESSAGE_DATA_FIELD(data) _MESSAGE_DATA_FIELD data

#define _MESSAGE_DATA_PACK_FIELD(pack_type, field_name) pack_type field_name;
#define MESSAGE_DATA_PACK_FIELD(data) _MESSAGE_DATA_PACK_FIELD data

#define BEGIN_MESSAGE(cmd)\
    struct message_##cmd : public c2pool::pool::Message {\
        message_##cmd() : c2pool::pool::Message(#cmd) {}\
        \

        // WRITE

        // READ TYPE

#define MESSAGE_FIELDS(...)\
    MESSAGE_DATA_EXPAND(MESSAGE_DATA_PASTE(MESSAGE_DATA_FIELD, __VA_ARGS__))\
    \
    struct packed_type\
    {\
        MESSAGE_DATA_EXPAND(MESSAGE_DATA_PASTE(MESSAGE_DATA_PACK_FIELD, __VA_ARGS__))\
    };

#define END_MESSAGE() };