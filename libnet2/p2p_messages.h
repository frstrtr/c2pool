#pragma once

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>
#include <libdevcore/types.h>
#include <sharechains/share_types.h>
#include <libp2p/message.h>

namespace pool::messages
{
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

    class message_version : public Message
    {
    public:
        IntType(32) version;
        IntType(64) services;
        stream::address_type_stream addr_to;
        stream::address_type_stream addr_from;
        IntType(64) nonce;
        StrType sub_version;
        IntType(32) mode; //# always 1 for legacy compatibility
        /*uint256*/
        PossibleNoneType<IntType(256)> best_share_hash;
        //PoolVersion pool_version;

    public:
        message_version() : Message("version"), best_share_hash(uint256()) {}

        message_version(int ver, int serv, address_type to, address_type from, unsigned long long _nonce, std::string sub_ver, int _mode, uint256 best_hash) : message_version()
        {
            version = ver;
            services = serv;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version = sub_ver;
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

    class message_ping : public Message
    {
    public:
        message_ping() : Message("ping") {}

        PackStream &write(PackStream &stream) override
        {
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            return stream;
        }
    };

    class message_addrme : public Message
    {
    public:
        IntType(16) port;

    public:
        message_addrme() : Message("addrme") {}

        message_addrme(int _port) : message_addrme()
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

    class message_getaddrs : public Message
    {
    public:
        IntType(32) count;

    public:
        message_getaddrs() : Message("getaddrs") {}

        message_getaddrs(int cnt) : message_getaddrs()
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

    class message_addrs : public Message
    {
    public:
        ListType<stream::addr_stream> addrs;

    public:
        message_addrs() : Message("addrs") {}

        message_addrs(std::vector<addr> _addrs) : message_addrs()
        {
            addrs = stream::addr_stream::make_list_type(_addrs);
        }

        message_addrs(std::vector<stream::addr_stream> _addrs) : message_addrs()
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

    class message_shares : public Message
    {
    public:
        ListType<PackedShareData> raw_shares;

    public:
        message_shares() : Message("shares") {}

        message_shares(std::vector<PackedShareData> _shares) : message_shares()
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

    class message_sharereq : public Message
    {
    public:
        IntType(256) id;
        ListType<IntType(256)> hashes;
        VarIntType parents;
        ListType<IntType(256)> stops;

    public:
        message_sharereq() : Message("sharereq") {}

        message_sharereq(uint256 _id, std::vector<uint256> _hashes, unsigned long long _parents, std::vector<uint256> _stops) : message_sharereq()
        {
            id = _id;
            hashes = hashes.make_type(_hashes);
            parents = _parents;
            stops = stops.make_type(_stops);
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

    class message_sharereply : public Message
    {
    public:
        IntType(256) id;
        EnumType<ShareReplyResult, VarIntType> result;
        ListType<PackedShareData> shares; //type + contents data

    public:
        message_sharereply() : Message("sharereply") {}

        message_sharereply(uint256 _id, ShareReplyResult _result, std::vector<PackedShareData> _shares) : message_sharereply()
        {
            id = _id;
            result = _result;
            shares = shares.make_type(_shares);
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

    class message_bestblock : public Message
    {
    public:
        coind::data::stream::BlockHeaderType_stream header;

    public:
        message_bestblock() : Message("bestblock") {}

        message_bestblock(coind::data::types::BlockHeaderType _header) : message_bestblock()
        {
            header = _header;
        }

        PackStream &write(PackStream &stream) override
        {
            stream << header;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> header;
            return stream;
        }
    };

    class message_have_tx : public Message
    {
    public:
        ListType<IntType(256)> tx_hashes;

    public:
        message_have_tx() : Message("have_tx") {}

        message_have_tx(std::vector<uint256> _tx_hashes) : message_have_tx()
        {
            tx_hashes = tx_hashes.make_type(_tx_hashes);
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

    class message_losing_tx : public Message
    {
    public:
        ListType<IntType(256)> tx_hashes;

    public:
        message_losing_tx() : Message("losing_tx") {}

        message_losing_tx(std::vector<uint256> _tx_hashes) : message_losing_tx()
        {
            tx_hashes = tx_hashes.make_type(_tx_hashes);
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

    class message_remember_tx : public Message
    {
    public:
        ListType<IntType(256)> tx_hashes;
        ListType<coind::data::stream::TransactionType_stream> txs;
    public:
        message_remember_tx() : Message("remember_tx") {}

        message_remember_tx(std::vector<uint256> _tx_hashes) : message_remember_tx()
        {
            tx_hashes = tx_hashes.make_type(_tx_hashes);
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

    class message_forget_tx : public Message
    {
    public:
        ListType<IntType(256)> tx_hashes;

    public:
        message_forget_tx() : Message("forget_tx") {}

        message_forget_tx(std::vector<uint256> _tx_hashes) : message_forget_tx()
        {
            tx_hashes = tx_hashes.make_type(_tx_hashes);
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
} // namespace net::messages