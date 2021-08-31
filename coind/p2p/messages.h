#pragma once

#include <univalue.h>
#include <btclibs/uint256.h>
#include <util/types.h>
using namespace c2pool::messages;
#include <networks/network.h>
#include <util/stream.h>
#include <util/stream_types.h>

#include <sstream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <tuple>
#include <map>

#include <devcore/logger.h>

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

    const char *string_commands(commands cmd);

    commands reverse_string_commands(const char *key);

    //base_message type for handle
    class raw_message
    {
        friend coind::p2p::P2PSocket;

    public:
        coind::p2p::messages::commands name_type;
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
        address_type addr_to;
        address_type addr_from;
        IntType(64) nonce;
        StrType sub_version;
        IntType(32) start_height;

    public:
        message_version() : base_message("version") {}

        message_version(int ver, int serv, int64_t _timestamp, address_type to, address_type from, unsigned long long _nonce, std::string sub_ver, int32_t _start_height) : base_message("version")
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

        message_ping(uint64_t _nonce) : base_message("ping")
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
        uint64_t nonce;

    public:
        message_pong() : base_message("pong") {}

        message_pong(uint64_t _nonce) : base_message("pong")
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
        ListType<c2pool::messages::addr> addrs;

    public:
        message_addr() : base_message("addr") {}

        message_addr(std::vector<c2pool::messages::addr> _addrs) : base_message("addr")
        {
            addrs = _addrs;
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
        ListType<inventory> invs;

    public:
        message_inv() : base_message("inv") {}

        message_inv(std::vector<inventory> _invs) : base_message("inv")
        {
            invs = _invs;
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
        ListType<inventory> requests;

    public:
        message_getdata() : base_message("getdata") {}

        message_getdata(std::vector<inventory> _reqs) : base_message("getdata")
        {
            requests = _reqs;
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
        IntType(256) last;

    public:
        message_getblocks() : base_message("getblocks") {}

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
        IntType(256) last;

    public:
        message_getheaders() : base_message("getheaders") {}

        message_getheaders(uint32_t _version, std::vector<uint256> _have, uint256 _last) : base_message("getheaders")
        {
            version = _version;
            have = _have;
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
        //TODO:
        /*
        message_tx = pack.ComposedType([
        ('tx', bitcoin_data.tx_type),
        ])
        */
        //TODO:UniValue tx;

    public:
        message_tx() : base_message("tx") {}

        PackStream &write(PackStream &stream) override
        {
            //TODO: stream << tx;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            //TODO: stream >> tx;
            return stream;
        }
    };

    class message_block : public base_message
    {
    public:
        //TODO:
        /*
        message_block = pack.ComposedType([
        ('block', bitcoin_data.block_type),
        ])
        */
        //TODO:UniValue block;

    public:
        message_block() : base_message("block") {}

        PackStream &write(PackStream &stream) override
        {
            //TODO: stream << block;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            //TODO: stream >> block;
            return stream;
        }
    };

    class message_headers : public base_message
    {
    public:
        //TODO:
        /*
        message_headers = pack.ComposedType([
        ('headers', pack.ListType(bitcoin_data.block_type)),
        ])
        */
        //TODO: UniValue headers;

    public:
        message_headers() : base_message("headers") {}

        PackStream &write(PackStream &stream) override
        {
            //TODO: stream << headers;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            //TODO: stream >> headers;
            return stream;
        }
    };
} // namespace c2pool::libnet::messages