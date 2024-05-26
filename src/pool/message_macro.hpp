#pragma once

#include <memory>
#include <core/macro.hpp>

// fields
#define _MESSAGE_DATA_FIELD(pack_type, field_name) pack_type::get_type m_##field_name;
#define MESSAGE_DATA_FIELD(data) _MESSAGE_DATA_FIELD data

#define _MESSAGE_DATA_FIELD_WRITE(pack_type, field_name) packed  .field_name = m_##field_name;
#define MESSAGE_DATA_FIELD_WRITE(data) _MESSAGE_DATA_FIELD_WRITE data

#define _MESSAGE_DATA_FIELD_READ(pack_type, field_name) m_##field_name = packed .field_name.get();
#define MESSAGE_DATA_FIELD_READ(data) _MESSAGE_DATA_FIELD_READ data

// pack_type
#define _MESSAGE_DATA_PACK_FIELD(pack_type, field_name) pack_type field_name;
#define MESSAGE_DATA_PACK_FIELD(data) _MESSAGE_DATA_PACK_FIELD data

#define _MESSAGE_DATA_PACK_WRITE(pack_type, field_name) stream << field_name;
#define MESSAGE_DATA_PACK_WRITE(data) _MESSAGE_DATA_PACK_WRITE data

#define _MESSAGE_DATA_PACK_READ(pack_type, field_name) stream >> field_name;
#define MESSAGE_DATA_PACK_READ(data) _MESSAGE_DATA_PACK_READ data

// args
#define _MESSAGE_DATA_MAKE_ARGS(pack_type, field_name) pack_type::get_type _##field_name
#define MESSAGE_DATA_MAKE_ARGS(data) _MESSAGE_DATA_MAKE_ARGS data

#define _MESSAGE_DATA_INIT_ARGS(pack_type, field_name) result->m_##field_name = _##field_name;
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
    struct packed_type\
    {\
        C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_PACK_FIELD, __VA_ARGS__))\
        \
        PackStream& write(PackStream& stream)\
        {\
            C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_PACK_WRITE, __VA_ARGS__))\
            return stream;\
        }\
        \
        PackStream &read(PackStream &stream)\
        {\
            C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_PACK_READ, __VA_ARGS__))\
            return stream;\
        }\
    };\
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
    \
    PackStream& write(PackStream& stream) override\
    {\
        packed_type packed;\
        C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_FIELD_WRITE, __VA_ARGS__))\
        stream << packed;\
        return stream;\
    }\
    \
    PackStream &read(PackStream &stream) override\
    {\
        packed_type packed;\
        stream >> packed;\
        C2POOL_EXPAND(C2POOL_MULTIPLE_CALL_MACRO(PASTE, MESSAGE_DATA_FIELD_READ, __VA_ARGS__))\
        return stream;\
    }\
    

#define END_MESSAGE() };