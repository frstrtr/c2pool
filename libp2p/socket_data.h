#pragma once

#include <cstdint>
#include <memory>

#include "message.h"
#include <libcoind/data.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
struct ReadPacket
{
    const int COMMAND_LEN = 12;
    const int LEN_LEN = 4;
    const int CHECKSUM_LEN = 4;

    char *prefix;
    char *command;
    char *len;
    char *checksum;
    char *payload;

    int32_t unpacked_len;

    ReadPacket(int32_t pref_len) : payload(nullptr)
    {
        prefix = new char[pref_len];
        command = new char[COMMAND_LEN];
        len = new char[LEN_LEN];
        checksum = new char[CHECKSUM_LEN];
    }

    ~ReadPacket()
    {
        delete[] prefix;
        delete[] command;
        delete[] len;
        delete[] checksum;
        if (payload)
        {
            delete[] payload;
        }
    }
};

// struct WritePacket
// {
//     char *data;
//     int32_t len;

//     WritePacket() {}
//     WritePacket(char *_data, int32_t _len) : 

//     ~WritePacket()
//     {
//         if (data != nullptr)
//         {
//             delete []data;
//         }
//     }

//     virtual void from_message(std::shared_ptr<Message> msg) = 0;
// };

struct WritePacket
{
    int32_t len;
    char *data {nullptr};
    std::vector<unsigned char> prefix;

    WritePacket(char *_data, int32_t _len) 
        : data(_data), len(_len) 
    { 

    }

    WritePacket(std::shared_ptr<Message> msg, const unsigned char *pref, int len)
    {
        prefix = std::vector<unsigned char>(pref, pref+len);
        from_message(std::move(msg));
    }

    void from_message(std::shared_ptr<Message> msg)
    {
        PackStream value;

        // prefix
        PackStream prefix_stream(prefix);
        value << prefix_stream;

        //command
        auto command = new char[12]{'\0'};
        memcpy(command, msg->command.c_str(), msg->command.size());
        PackStream s_command(command, 12);
        value << s_command;
        delete[] command;

        //-----
        PackStream payload_stream;
        payload_stream << *msg;

        //len
        IntType(32) unpacked_len(payload_stream.size());
        value << unpacked_len;

        //checksum
        PackStream payload_checksum_stream;
        payload_checksum_stream << *msg;

        auto _checksum = coind::data::hash256(payload_checksum_stream, false);

        IntType(256) checksum_full(_checksum);
        PackStream _packed_checksum;
        _packed_checksum << checksum_full;
        vector<unsigned char> packed_checksum(_packed_checksum.data.end() - 4, _packed_checksum.data.end());
        std::reverse(packed_checksum.begin(), packed_checksum.end());
        PackStream checksum(packed_checksum);
        value << checksum;

        //payload
        value << payload_stream;

        //result
        data = new char[value.size()];
        memcpy(data, value.bytes(), value.size());
        len = value.size();
    }

    friend std::ostream &operator<<(std::ostream &stream, WritePacket &v)
    {
        if (v.len > 400)
        {
            stream << "Msg too long for print, len = " << v.len;
        } else
        {
            stream << "[ ";
            for (auto _v = v.data; _v != v.data+v.len; _v++)
            {
                stream << (unsigned int)((unsigned char) *_v) << " ";
            }
            stream << "]";
        }
        return stream;
    }
};

template <typename SocketType, typename PacketType>
class SocketPacketType
{
    using socket_type = std::shared_ptr<SocketType>;
    using packet_type = PacketType;

public:
    using ptr_type = std::shared_ptr<SocketPacketType<SocketType, PacketType>>;

    socket_type socket;
    packet_type value;
    
    template <typename...Args>
    static ptr_type make(const socket_type& socket_, Args...args)
    {
        return std::make_shared<SocketPacketType<SocketType, PacketType>>(socket_, args...);
    }

    template <typename...Args>
    SocketPacketType(const socket_type& socket_, Args...args) 
        : socket(socket_), value(args...)
    {
        
    }
};