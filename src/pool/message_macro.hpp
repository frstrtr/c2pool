#pragma once

#include <memory>
#include <core/macro.hpp>

// fields
#define _MESSAGE_DATA_FIELD(pack_type, field_name) pack_type field_name;
#define MESSAGE_DATA_FIELD(data) _MESSAGE_DATA_FIELD data

// args
#define _MESSAGE_DATA_MAKE_ARGS(pack_type, field_name) pack_type _##field_name
#define MESSAGE_DATA_MAKE_ARGS(data) _MESSAGE_DATA_MAKE_ARGS data

#define _MESSAGE_DATA_INIT_ARGS(pack_type, field_name) result ->field_name = _##field_name;
#define MESSAGE_DATA_INIT_ARGS(data) _MESSAGE_DATA_INIT_ARGS data


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
    static std::unique_ptr<message_type> make(C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(ENUMERATE, MESSAGE_DATA_MAKE_ARGS, __VA_ARGS__)))\
    {\
        auto result = std::make_unique<message_type>();\
        C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_INIT_ARGS, __VA_ARGS__));\
        return result;\
    }\
    \
    static std::unique_ptr<message_type> make(PackStream& stream)\
    {\
        auto result = std::make_unique<message_type>();\
        stream >> *result;\
        return result;\
    }\
    SERIALIZE_METHODS(message_type)
    
#define WITHOUT_MESSAGE_FIELDS()\
    static std::unique_ptr<message_type> make()\
    {\
        auto result = std::make_unique<message_type>();\
        return result;\
    }\
    \
    static std::unique_ptr<message_type> make(PackStream& stream)\
    {\
        auto result = std::make_unique<message_type>();\
        return result;\
    }\
    SERIALIZE_METHODS(message_type)


#define END_MESSAGE() };