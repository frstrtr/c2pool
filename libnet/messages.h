#pragma once

#include <sstream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <tuple>

#include <univalue.h>
#include <util/types.h>
#include <util/stream_types.h>
#include <btclibs/uint256.h>
#include <sharechains/shareTypes.h>
#include <networks/network.h>
#include <devcore/logger.h>

using namespace c2pool::messages;

namespace c2pool::libnet::p2p
{
    class P2PSocket;
}

namespace c2pool::libnet::messages
{
    enum commands
    {
        cmd_error = 9999,
        cmd_version = 0,
        cmd_ping,
        cmd_addrme,
        cmd_addrs,
        cmd_getaddrs,

        //new:
        cmd_shares,
        cmd_sharereq,
        cmd_sharereply,
        cmd_best_block, //TODO
        cmd_have_tx,
        cmd_losing_tx
    };

    const std::map<commands, const char *> _string_commands = {
        {cmd_error, "error"},
        {cmd_version, "version"},
        {cmd_ping, "ping"},
        {cmd_addrme, "addrme"},
        {cmd_addrs, "addrs"},
        {cmd_getaddrs, "getaddrs"},
        //
        {cmd_shares, "shares"},
        {cmd_sharereq, "sharereq"},
        {cmd_sharereply, "sharereply"},
        {cmd_best_block, "best_block"},
        {cmd_have_tx, "have_tx"},
        {cmd_losing_tx, "losing_tx"}};

    const std::map<const char *, commands> _reverse_string_commands = {
        {"error", cmd_error},
        {"version", cmd_version},
        {"ping", cmd_ping},
        {"addrme", cmd_addrme},
        {"addrs", cmd_addrs},
        {"getaddrs", cmd_getaddrs},
        //
        {"shares", cmd_shares},
        {"sharereq", cmd_sharereq},
        {"sharereply", cmd_sharereply},
        {"best_block", cmd_best_block},
        {"have_tx", cmd_have_tx},
        {"losing_tx", cmd_losing_tx}};

    const char *string_commands(commands cmd);

    commands reverse_string_commands(const char *key);

    //base_message type for handle
    class raw_message
    {
        friend c2pool::libnet::p2p::P2PSocket;

    public:
        EnumType<c2pool::libnet::messages::commands> name_type;
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
        address_type addr_to;
        address_type addr_from;
        IntType(64) nonce;
        StrType sub_version;
        IntType(32) mode; //# always 1 for legacy compatibility
        /*uint256*/
        PossibleNoneType<IntType(256)> best_share_hash;
        //PoolVersion pool_version;

    public:
        message_version() : base_message("version") {}

        message_version(int ver, int serv, address_type to, address_type from, unsigned long long _nonce, std::string sub_ver, int _mode, uint256 best_hash, PoolVersion pool_ver = PoolVersion::None) : base_message("version")
        {
            version = ver;
            services = serv;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version.str = sub_ver;
            mode = _mode;
            best_share_hash = PossibleNoneType<IntType(256)>::make_type(best_hash);
            //pool_version = pool_ver;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << version << services << addr_to << addr_from << nonce << sub_version << mode << best_share_hash;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> version >> services >> addr_to >> addr_from >> nonce >> sub_version >> mode >> best_share_hash;
            return stream;
        }
    };

    class message_ping : public base_message
    {
    public:
        message_ping() : base_message("ping") {}

        PackStream &write(PackStream &stream) override
        {
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            return stream;
        }
    };

    class message_addrme : public base_message
    {
    public:
        IntType(16) port;

    public:
        message_addrme() : base_message("addrme") {}

        message_addrme(int _port) : base_message("addrme")
        {
            port = _port;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << port;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> port;
            return stream;
        }
    };

    class message_getaddrs : public base_message
    {
    public:
        IntType(32) count;

    public:
        message_getaddrs() : base_message("getaddrs") {}

        message_getaddrs(int cnt) : base_message("getaddrs")
        {
            count = cnt;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << count;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> count;
            return stream;
        }
    };

    class message_addrs : public base_message
    {
    public:
        ListType<c2pool::messages::addr> addrs;

    public:
        message_addrs() : base_message("addrs") {}

        message_addrs(std::vector<c2pool::messages::addr> _addrs) : base_message("addrs")
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

    //TODO
    class message_shares : public base_message
    {
    public:
        std::vector<UniValue> raw_shares;

    public:
        message_shares() : base_message("shares") {}

        message_shares(std::vector<UniValue> _shares) : base_message("shares")
        {
            raw_shares = _shares;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << raw_shares;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> raw_shares;
            return stream;
        }
    };

    class message_sharereq : public base_message
    {
    public:
        IntType(256) id;
        ListType<IntType(256)> hashes;
        VarIntType parents;
        ListType<IntType(256)> stops;

    public:
        message_sharereq() : base_message("sharereq") {}

        message_sharereq(uint256 _id, std::vector<uint256> _hashes, unsigned long long _parents, std::vector<uint256> _stops) : base_message("sharereq")
        {
            id = _id;
            hashes = hashes.make_list_type(_hashes);
            parents = _parents;
            stops = stops.make_list_type(_stops);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << id << hashes << parents << stops;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> id >> hashes >> parents >> stops;
            return stream;
        }
    };

    enum ShareReplyResult
    {
        good = 0,
        too_long = 1,
        unk2 = 2,
        unk3 = 3,
        unk4 = 4,
        unk5 = 5,
        unk6 = 6
    };

    class message_sharereply : public base_message
    {
    public:
        IntType(256) id;
        EnumType<ShareReplyResult, VarIntType> result;
        ListType<UniValue> shares; //type + contents data

    public:
        message_sharereply() : base_message("sharereply") {}

        message_sharereply(uint256 _id, ShareReplyResult _result, std::vector<UniValue> _shares) : base_message("sharereply")
        {
            id = _id;
            result = _result;
            shares = _shares;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << id << result << shares;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> id >> result >> shares;
            return stream;
        }
    };

    class message_have_tx : public base_message
    {
    public:
        ListType<IntType(256)> tx_hashes;

    public:
        message_have_tx() : base_message("have_tx") {}

        message_have_tx(std::vector<uint256> _tx_hashes) : base_message("have_tx")
        {
            tx_hashes = tx_hashes.make_list_type(_tx_hashes);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << tx_hashes;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> tx_hashes;
            return stream;
        }
    };

    class message_losing_tx : public base_message
    {
    public:
        ListType<IntType(256)> tx_hashes;

    public:
        message_losing_tx() : base_message("losing_tx") {}

        message_losing_tx(std::vector<uint256> _tx_hashes) : base_message("losing_tx")
        {
            tx_hashes = tx_hashes.make_list_type(_tx_hashes);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << tx_hashes;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> tx_hashes;
            return stream;
        }
    };

} // namespace c2pool::libnet::messages