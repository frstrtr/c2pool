#pragma once

#include <libcoind/data.h>
#include <libp2p/socket_data.h>

#include <utility>

struct P2PWriteSocketData : public WriteSocketData
{
    std::vector<unsigned char> prefix;

    P2PWriteSocketData() : WriteSocketData() { }
    P2PWriteSocketData(char *_data, int32_t _len) : WriteSocketData(_data, _len) { }

    P2PWriteSocketData(std::shared_ptr<Message> msg, const unsigned char *pref, int len) : WriteSocketData()
    {
        prefix = std::vector<unsigned char>(pref, pref+len);
        from_message(std::move(msg));
    }

    void from_message(std::shared_ptr<Message> msg) override
    {
        PackStream value;

        // prefix [+]
        PackStream prefix_stream(prefix);
        value << prefix_stream;

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

        auto _checksum = coind::data::hash256(payload_checksum_stream, false);

        IntType(256) checksum_full(_checksum);
        PackStream _packed_checksum;
        _packed_checksum << checksum_full;
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

    friend std::ostream &operator<<(std::ostream &stream, P2PWriteSocketData &v)
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