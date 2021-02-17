#include "p2p_protocol.h"
#include "p2p_socket.h"
#include "messages.h"
using namespace c2pool::libnet::messages;

namespace c2pool::p2p{
    Protocol::Protocol(P2PSocket socket) : _socket(std::move(socket)){

    }

    void Protocol::handle(shared_ptr<raw_message> RawMSG)
        {
            //В Python скрипте, команда передается, как int, эквивалентный commands

            switch (RawMSG->name_type) //todo: switch -> if (" " == cmd)
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

        void Protocol::handle(shared_ptr<message_version> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_addrs> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_addrme> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_ping> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_getaddrs> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_error> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_shares> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_sharereq> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_sharereply> msg)
        {
            //TODO:
        }

        //TODO:
        // void Protocol::handle(message_best_block *msg)
        // {
        // }

        void Protocol::handle(shared_ptr<message_have_tx> msg)
        {
            //TODO:
        }

        void Protocol::handle(shared_ptr<message_losing_tx> msg)
        {
            //TODO:
        }
}