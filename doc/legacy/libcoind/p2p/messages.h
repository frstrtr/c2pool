#pragma once

#include <sstream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <tuple>
#include <map>

#include <libdevcore/logger.h>
#include <btclibs/uint256.h>
#include <libdevcore/types.h>
#include <networks/network.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>
#include <libcoind/transaction.h>
#include <libcoind/types.h>

#include <univalue.h>

namespace coind::p2p
{
    class P2PSocket;
}

namespace coind::p2p::messages
{
    enum commands
    {
        cmd_error = 9999,
        cmd_version = 0,
        cmd_verack,
        cmd_ping,
        cmd_pong,
        cmd_alert,
        cmd_getaddr,
        cmd_addr,
        cmd_inv,
        cmd_getdata,
        cmd_reject,
        cmd_getblocks,
        cmd_getheaders,
        cmd_tx,
        cmd_block,
        cmd_headers
    };

    const std::map<commands, const char *> _string_commands = {
        {cmd_error, "error"},
        {cmd_version, "version"},
        {cmd_verack, "verack"},
        {cmd_ping, "ping"},
        {cmd_pong, "pong"},
        {cmd_alert, "alert"},
        {cmd_getaddr, "getaddr"},
        {cmd_addr, "addr"},
        {cmd_inv, "inv"},
        {cmd_getdata, "getdata"},
        {cmd_reject, "reject"},
        {cmd_getblocks, "getblocks"},
        {cmd_getheaders, "getheaders"},
        {cmd_tx, "tx"},
        {cmd_block, "block"},
        {cmd_headers, "headers"}};

    const std::map<const char *, commands> _reverse_string_commands = {
        {"error", cmd_error},
        {"version", cmd_version},
        {"verack", cmd_verack},
        {"ping", cmd_ping},
        {"pong", cmd_pong},
        {"alert", cmd_alert},
        {"getaddr", cmd_getaddr},
        {"addr", cmd_addr},
        {"inv", cmd_inv},
        {"getdata", cmd_getdata},
        {"reject", cmd_reject},
        {"getblocks", cmd_getblocks},
        {"getheaders", cmd_getheaders},
        {"tx", cmd_tx},
        {"block", cmd_block},
        {"headers", cmd_headers}};

    inline const char *string_coind_commands(commands cmd)
    {
        try
        {
            return _string_commands.at(cmd);
        }
        catch (const std::out_of_range &e)
        {
            LOG_WARNING << (int)cmd << " out of range in string_coind_commands";
            return "error";
        }
    }

    inline commands reverse_string_commands(const char *key)
    {
        try
        {
            return _reverse_string_commands.at(key);
        }
        catch (const std::out_of_range &e)
        {
            LOG_WARNING << key << " out of range in reverse_string_commands";
            return commands::cmd_error;
        }
    }

    //base_message type for handle
    class raw_message
    {
        friend coind::p2p::P2PSocket;

    public:
        EnumType<coind::p2p::messages::commands> name_type;
        PackStream value;

    public:
        raw_message()
        {
        }

        PackStream &write(PackStream &stream)
        {
            stream << name_type << value;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> name_type;
            value = PackStream(stream);
            return stream;
        }
    };

    class base_message
    {
    public:
        commands cmd;

    public:
        base_message(const char *_cmd)
        {
            cmd = reverse_string_commands(_cmd);
        }

        base_message(commands _cmd)
        {
            cmd = _cmd;
        }

    public:
        virtual PackStream &write(PackStream &stream) { return stream; };

        virtual PackStream &read(PackStream &stream) { return stream; };
    };

    /*
    template <class converter_type>
    class message_addrs
    {
    public:
        message_addrs(UniValue v) {}
    };
    */

    class message_error : public base_message
    {
    public:
        StrType command;
        StrType error_text;

    public:
        message_error() : base_message("error") {}

        PackStream &write(PackStream &stream) override
        {
            stream << command << error_text;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> command >> error_text;
            return stream;
        }
    };

    enum PoolVersion
    {
        None = 0,
        C2Pool = 1
    };

    class message_version : public base_message
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
        message_version() : base_message("version") {}

        message_version(int32_t ver, int64_t serv, int64_t _timestamp, address_type to, address_type from, uint64_t _nonce, std::string sub_ver, int32_t _start_height) : base_message("version")
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

    class message_verack : public base_message
    {
    public:
        message_verack() : base_message("verack") {}

        PackStream &write(PackStream &stream) override
        {
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            return stream;
        }
    };

    class message_ping : public base_message
    {
    public:
        IntType(64) nonce;

    public:
        message_ping() : base_message("ping") {}

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

    class message_pong : public base_message
    {
    public:
        IntType(64) nonce;

    public:
        message_pong() : base_message("pong") {}

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

    class message_alert : public base_message
    {
    public:
        StrType message;
        StrType signature;

    public:
        message_alert() : base_message("alert") {}

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

    class message_getaddr : public base_message
    {
    public:

    public:
        message_getaddr() : base_message("getaddr") {}

        PackStream &write(PackStream &stream) override
        {
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            return stream;
        }
    };

    class message_addr : public base_message
    {
    public:
        ListType<stream::addr_stream> addrs;

    public:
        message_addr() : base_message("addr") {}

        message_addr(std::vector<addr> _addrs) : base_message("addr")
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

    class message_inv : public base_message
    {
    public:
        ListType<stream::inventory_stream> invs;

    public:
        message_inv() : base_message("inv") {}

        message_inv(std::vector<inventory> _invs) : message_inv()
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

    class message_getdata : public base_message
    {
    public:
        ListType<stream::inventory_stream> requests;

    public:
        message_getdata() : base_message("getdata") {}

        message_getdata(std::vector<inventory> _reqs) : message_getdata()
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

    class message_reject : public base_message
    {
    public:
        StrType message;
        IntType(8) ccode;
        StrType reason;
        IntType(256) data;

    public:
        message_reject() : base_message("reject") {}

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

    class message_getblocks : public base_message
    {
    public:
        IntType(32) version;
        ListType<IntType(256)> have;
        PossibleNoneType<IntType(256)> last;

    public:
        message_getblocks() : base_message("getblocks"), last(uint256::ZERO) {}

        message_getblocks(int32_t _version, std::vector<uint256> _have, uint256 _last) : message_getblocks()
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

    class message_getheaders : public base_message
    {
    public:
        IntType(32) version;
        ListType<IntType(256)> have;
        PossibleNoneType<IntType(256)> last;

    public:
        message_getheaders() : base_message("getheaders"), last(uint256::ZERO) {}

        message_getheaders(int32_t _version, std::vector<uint256> _have, uint256 _last) : message_getheaders()
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

    class message_tx : public base_message
    {
    public:
        coind::data::stream::TransactionType_stream tx;

    public:
        message_tx() : base_message("tx") {}

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

    class message_block : public base_message
    {
    public:
        coind::data::stream::BlockType_stream block;

    public:
        message_block() : base_message("block") {}

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

    class message_headers : public base_message
    {
    public:
        ListType<coind::data::stream::BlockType_stream> headers;

    public:
        message_headers() : base_message("headers") {}

        message_headers(std::vector<coind::data::types::BlockType> _headers) : message_headers()
        {
            std::vector<coind::data::stream::BlockType_stream> temp_headers;
            std::transform(_headers.begin(), _headers.end(), temp_headers.begin(), [&](coind::data::types::BlockType header){
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
} // namespace c2pool::libnet::messages