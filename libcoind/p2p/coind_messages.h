#pragma once

#include <libdevcore/stream_types.h>
#include <libdevcore/stream.h>
#include <libdevcore/types.h>
#include <libcoind/transaction.h>
#include <libcoind/data.h>
#include <libcoind/types.h>
#include <libp2p/message.h>

namespace coind::messages
{
    enum PoolVersion
    {
        None = 0,
        C2Pool = 1
    };

    class message_version : public Message
    {
    public:
        IntType(32) version;
        IntType(64) services;
        IntType(64) timestamp;
        stream::address_type_stream addr_to;
        stream::address_type_stream addr_from;
        IntType(64) nonce;
        StrType sub_version;
        IntType(32) start_height;

    public:
        message_version() : Message("version")
        {}

        message_version(int32_t ver, int64_t serv, int64_t _timestamp, address_type to, address_type from,
                        uint64_t _nonce, std::string sub_ver, int32_t _start_height) : message_version()
        {
            version = ver;
            services = serv;
            timestamp = _timestamp;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version = sub_ver;
            start_height = _start_height;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << version << services << timestamp << addr_to << addr_from << nonce << sub_version << start_height;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> version >> services >> timestamp >> addr_to >> addr_from >> nonce >> sub_version >> start_height;
            return stream;
        }
    };

    class message_verack : public Message
    {
    public:
        message_verack() : Message("verack") {}

        PackStream &write(PackStream &stream) override
        {
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            return stream;
        }
    };

    class message_ping : public Message
    {
    public:
        IntType(64) nonce;

    public:
        message_ping() : Message("ping")
        {}

        message_ping(uint64_t _nonce) : message_ping()
        {
            nonce = _nonce;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << nonce;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> nonce;
            return stream;
        }
    };

    class message_pong : public Message
    {
    public:
        IntType(64) nonce;

    public:
        message_pong() : Message("pong") {}

        message_pong(uint64_t _nonce) : message_pong()
        {
            nonce = _nonce;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << nonce;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> nonce;
            return stream;
        }
    };

    class message_alert : public Message
    {
    public:
        StrType message;
        StrType signature;

    public:
        message_alert() : Message("alert")
        {}

        message_alert(std::string _message, std::string _signature) : message_alert()
        {
            message = _message;
            signature = _signature;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << message << signature;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> message >> signature;
            return stream;
        }
    };

    class message_getaddr : public Message
    {
    public:

    public:
        message_getaddr() : Message("getaddr")
        {}

        PackStream &write(PackStream &stream) override
        {
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            return stream;
        }
    };

    class message_addr : public Message
    {
    public:
        ListType<stream::addr_stream> addrs;

    public:
        message_addr() : Message("addr") {}

        message_addr(std::vector <addr> _addrs) : message_addr()
        {
            addrs = stream::addr_stream::make_list_type(_addrs);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << addrs;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> addrs;
            return stream;
        }
    };

    class message_inv : public Message
    {
    public:
        ListType<stream::inventory_stream> invs;

    public:
        message_inv() : Message("inv") { }

        message_inv(std::vector <inventory> _invs) : message_inv()
        {
            invs = stream::inventory_stream::make_list_type(_invs);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << invs;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> invs;
            return stream;
        }
    };

    class message_getdata : public Message
    {
    public:
        ListType<stream::inventory_stream> requests;

    public:
        message_getdata() : Message("getdata") {}

        message_getdata(std::vector <inventory> _reqs) : message_getdata()
        {
            requests = stream::inventory_stream::make_list_type(_reqs);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << requests;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> requests;
            return stream;
        }
    };

    class message_reject : public Message
    {
    public:
        StrType message;
        IntType(8) ccode;
        StrType reason;
        IntType(256) data;

    public:
        message_reject() : Message("reject") { }

        message_reject(std::string _message, uint8_t _ccode, std::string _reason, uint256 _data) : message_reject()
        {
            message = _message;
            ccode = _ccode;
            reason = _reason;
            data = _data;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << message << ccode << reason << data;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> message >> ccode >> reason >> data;
            return stream;
        }
    };

    class message_getblocks : public Message
    {
    public:
        IntType(32) version;
        ListType<IntType(256)> have;
        PossibleNoneType<IntType(256)> last;

    public:
        message_getblocks() : Message("getblocks"), last(uint256::ZERO) { }

        message_getblocks(int32_t _version, std::vector <uint256> _have, uint256 _last) : message_getblocks()
        {
            version = _version;
            have = IntType(256)::make_list_type(_have);
            last = _last;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << version << have << last;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> version >> have >> last;
            return stream;
        }
    };

    class message_getheaders : public Message
    {
    public:
        IntType(32) version;
        ListType<IntType(256)> have;
        PossibleNoneType<IntType(256)> last;

    public:
        message_getheaders() : Message("getheaders"), last(uint256::ZERO) {}

        message_getheaders(int32_t _version, std::vector <uint256> _have, uint256 _last) : message_getheaders()
        {
            version = _version;
            have = IntType(256)::make_list_type(_have);
            last = _last;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << version << have << last;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> version >> have >> last;
            return stream;
        }
    };

    class message_tx : public Message
    {
    public:
        coind::data::stream::TransactionType_stream tx;

    public:
        message_tx() : Message("tx") {}

        message_tx(coind::data::tx_type _tx) : message_tx()
        {
            tx = _tx;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << tx;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> tx;
            return stream;
        }
    };

    class message_block : public Message
    {
    public:
        coind::data::stream::BlockType_stream block;

    public:
        message_block() : Message("block")
        {}

        message_block(coind::data::types::BlockType _block) : message_block()
        {
            block = coind::data::stream::BlockType_stream(_block);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << block;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> block;
            return stream;
        }
    };

    class message_headers : public Message
    {
    public:
        ListType <coind::data::stream::BlockType_stream> headers;

    public:
        message_headers() : Message("headers")
        {}

        message_headers(std::vector <coind::data::types::BlockType> _headers) : message_headers()
        {
            std::vector <coind::data::stream::BlockType_stream> temp_headers;
            std::transform(_headers.begin(), _headers.end(), temp_headers.begin(),
                           [&](coind::data::types::BlockType header)
                           {
                               return coind::data::stream::BlockType_stream(header);
                           });
            headers = temp_headers;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << headers;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> headers;
            return stream;
        }
    };
}