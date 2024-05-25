#pragma once

#include <memory>
#include <core/macro.hpp>

#define _MESSAGE_DATA_FIELD(pack_type, field_name) pack_type::get_type m_##field_name;
#define MESSAGE_DATA_FIELD(data) _MESSAGE_DATA_FIELD data

#define _MESSAGE_DATA_PACK_FIELD(pack_type, field_name) pack_type field_name;
#define MESSAGE_DATA_PACK_FIELD(data) _MESSAGE_DATA_PACK_FIELD data

#define _MESSAGE_DATA_MAKE_ARGS(pack_type, field_name) pack_type::get_type _##field_name
#define MESSAGE_DATA_MAKE_ARGS(data) _MESSAGE_DATA_MAKE_ARGS data

#define BEGIN_MESSAGE(cmd)\
    class message_##cmd : public c2pool::pool::Message {\
    private:\
        using message_type = message_##cmd;\
    public:\
        message_##cmd() : c2pool::pool::Message(#cmd) {}\
        \
        // WRITE

        // READ TYPE

#define MESSAGE_FIELDS(...)\
    C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_FIELD, __VA_ARGS__))\
    \
    struct packed_type\
    {\
        C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_PACK_FIELD, __VA_ARGS__))\
    };\
    \
    static std::unique_ptr<message_type> make(C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(ENUMERATE, MESSAGE_DATA_MAKE_ARGS, __VA_ARGS__)))\
    {\
        return std::make_unique<message_type>();\
    }\

#define END_MESSAGE() };