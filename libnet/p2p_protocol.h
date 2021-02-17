#pragma once
#include "p2p_socket.h"
#include "messages.h"
using namespace c2pool::libnet::messages;

#include <lib/univalue/include/univalue.h>

#include <memory>
using std::shared_ptr, std::make_shared;

namespace c2pool::p2p
{
    class Protocol
    {
    public:
        Protocol(P2PSocket socket);

        void handle(shared_ptr<raw_message> RawMSG);

    protected:
        template <class MsgType>
        shared_ptr<MsgType> GenerateMsg(UniValue &value)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            *msg = value;
            return msg;
        }

        void handle(shared_ptr<message_version> msg);
        void handle(shared_ptr<message_addrs> msg);
        void handle(shared_ptr<message_addrme> msg);
        void handle(shared_ptr<message_ping> msg);
        void handle(shared_ptr<message_getaddrs> msg);
        void handle(shared_ptr<message_error> msg);
        void handle(shared_ptr<message_shares> msg);
        void handle(shared_ptr<message_sharereq> msg);
        void handle(shared_ptr<message_sharereply> msg);
        //TODO:
        // void handle(shared_ptr<message_best_block> msg);
        void handle(shared_ptr<message_have_tx> msg);
        void handle(shared_ptr<message_losing_tx> msg);

    private:
        P2PSocket _socket;
    };
} // namespace c2pool::p2p