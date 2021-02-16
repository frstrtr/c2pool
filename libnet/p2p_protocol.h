#pragma once
#include "p2p_socket.h"
#include "messages.h"
using namespace c2pool::libnet::messages;

#include <lib/univalue/include/univalue.h>

namespace c2pool::p2p
{
    class Protocol
    {
    public:
        Protocol(P2PSocket socket);

        void Protocol::handle(UniValue &value)
        {
            //В Python скрипте, команда передается, как int, эквивалентный commands
            int cmd;
            cmd = value["name_type"].get_int();
            auto json = value["value"].get_obj();

            switch (cmd) //todo: switch -> if (" " == cmd)
            {
            case commands::cmd_addrs:
                handle(GenerateMsg<message_addrs>(json));
                break;
            case commands::cmd_version:
                handle(GenerateMsg<message_version>(json));
                break;
            case commands::cmd_ping:
                handle(GenerateMsg<message_ping>(json));
                break;
            case commands::cmd_addrme:
                handle(GenerateMsg<message_addrme>(json));
                break;
            case commands::cmd_getaddrs:
                handle(GenerateMsg<message_getaddrs>(json));
                break;
            //new:
            case commands::cmd_shares:
                handle(GenerateMsg<message_shares>(json));
                break;
            case commands::cmd_sharereq:
                handle(GenerateMsg<message_sharereq>(json));
                break;
            case commands::cmd_sharereply:
                handle(GenerateMsg<message_sharereply>(json));
                break;
            //TODO:
            // case commands::cmd_best_block:
            //     handle(GenerateMsg<message_best_block>(json));
            //     break;
            case commands::cmd_have_tx:
                handle(GenerateMsg<message_have_tx>(json));
                break;
            case commands::cmd_losing_tx:
                handle(GenerateMsg<message_losing_tx>(json));
                break;
            default:
                handle(GenerateMsg<message_error>(json));
                break;
            }
        }

    protected:
        template <class MsgType>
        MsgType *Protocol::GenerateMsg(UniValue &value)
        {
            MsgType *msg = new MsgType();
            shared_ptr<MsgType> = std::make_shared<MsgType>();
            *msg = value;
            return msg;
        }

        void Protocol::handle(message_version *msg)
        {

            //TODO:
        }

        void Protocol::handle(message_addrs *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_addrme *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_ping *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_getaddrs *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_error *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_shares *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_sharereq *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_sharereply *msg)
        {
            //TODO:
        }

        //TODO:
        // void Protocol::handle(message_best_block *msg)
        // {
        // }

        void Protocol::handle(message_have_tx *msg)
        {
            //TODO:
        }

        void Protocol::handle(message_losing_tx *msg)
        {
            //TODO:
        }

    private:
        P2PSocket _socket;
    };
} // namespace c2pool::p2p