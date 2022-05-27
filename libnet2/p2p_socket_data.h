#pragma once

#include <libcoind/data.h>
#include <libp2p/socket_data.h>

struct P2PWriteSocketData : public WriteSocketData
{
    P2PWriteSocketData() : WriteSocketData() { }
    P2PWriteSocketData(char *_data, int32_t _len) : WriteSocketData(_data, _len) { }

    P2PWriteSocketData(std::shared_ptr<Message> msg) : WriteSocketData()
    {
        from_message(msg);
    }

    void from_message(std::shared_ptr<Message> msg) override
    {
        PackStream value;

//command [+]
        auto command = new char[12]{'\0'};
        memcpy(command, msg->command.c_str(), msg->command.size());
        PackStream s_command(command, 12);
        value << s_command;
        delete[] command;

//-----
        PackStream payload_stream;
        payload_stream << *msg;

//len [+]
        IntType(32) unpacked_len(payload_stream.size());
        value << unpacked_len;

//checksum [+]
        PackStream payload_checksum_stream;
        payload_checksum_stream << *msg;

        auto __checksum = coind::data::hash256(payload_checksum_stream);
        IntType(256) checksum_full(__checksum);
        PackStream _packed_checksum;
        _packed_checksum << checksum_full;
//TODO: почему результат реверснутый?
        vector<unsigned char> packed_checksum(_packed_checksum.data.end() - 4, _packed_checksum.data.end());
        std::reverse(packed_checksum.begin(), packed_checksum.end());
        PackStream checksum(packed_checksum);
        value << checksum;

//payload [+]
        value << payload_stream;

//result
        data = new char[value.size()];
        memcpy(data, value.bytes(), value.size());
        len = value.size();
    }

};