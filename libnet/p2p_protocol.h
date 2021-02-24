#pragma once

#include "messages.h"
#include "converter.h"
using namespace c2pool::libnet::messages;

#include <lib/univalue/include/univalue.h>

#include <memory>
using std::shared_ptr, std::weak_ptr, std::make_shared;

namespace c2pool::libnet::p2p
{
    class P2PSocket;
}

namespace c2pool::libnet::p2p
{
    class Protocol
    {
    protected:
        shared_ptr<c2pool::libnet::p2p::P2PSocket> _socket;

    protected:
        Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> _sct)
        {
            _socket = _sct;
        }

    public:
        virtual void handle(shared_ptr<raw_message> RawMSG) = 0;

        virtual shared_ptr<raw_message> make_raw_message() = 0;
    };

    template <class converter_type>
    class P2P_Protocol : public Protocol
    {
    public:
        P2P_Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket) : Protocol(socket)
        {
        }

        void handle(shared_ptr<raw_message> RawMSG) override
        {
            //В Python скрипте, команда передается, как int, эквивалентный commands

            UniValue json_value = RawMSG->value;

            switch (RawMSG->name_type) //todo: switch -> if (" " == cmd)
            {
            case commands::cmd_addrs:
                handle(GenerateMsg<message_addrs>(json_value));
                break;
            case commands::cmd_version:
                handle(GenerateMsg<message_version>(json_value));
                break;
            case commands::cmd_ping:
                handle(GenerateMsg<message_ping>(json_value));
                break;
            case commands::cmd_addrme:
                handle(GenerateMsg<message_addrme>(json_value));
                break;
            case commands::cmd_getaddrs:
                handle(GenerateMsg<message_getaddrs>(json_value));
                break;
            //new:
            case commands::cmd_shares:
                handle(GenerateMsg<message_shares>(json_value));
                break;
            case commands::cmd_sharereq:
                handle(GenerateMsg<message_sharereq>(json_value));
                break;
            case commands::cmd_sharereply:
                handle(GenerateMsg<message_sharereply>(json_value));
                break;
            //TODO:
            // case commands::cmd_best_block:
            //     handle(GenerateMsg<message_best_block>(json_value));
            //     break;
            case commands::cmd_have_tx:
                handle(GenerateMsg<message_have_tx>(json_value));
                break;
            case commands::cmd_losing_tx:
                handle(GenerateMsg<message_losing_tx>(json_value));
                break;
            default:
                handle(GenerateMsg<message_error>(json_value));
                break;
            }
        }

        shared_ptr<raw_message> make_raw_message() override
        {
            auto raw_msg = make_shared<raw_message>();
            raw_msg->set_converter_type<converter_type>();
            return raw_msg;
        }

    protected:
        template <class MsgType>
        //template <class MsgType<>, class ct = converter_type>
        shared_ptr<MsgType> GenerateMsg(UniValue &value)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            msg->template set_converter_type<converter_type>();
            *msg = value;
            return msg;
        }

        void handle(shared_ptr<message_version> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_addrs> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_addrme> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_ping> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_getaddrs> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_error> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_shares> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_sharereq> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_sharereply> msg)
        {
            //TODO:
        }
        //TODO:
        // void handle(shared_ptr<message_best_block> msg){
        //TODO:
        //}
        void handle(shared_ptr<message_have_tx> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_losing_tx> msg)
        {
            //TODO:
        }
    };

    typedef P2P_Protocol<c2pool::libnet::messages::p2pool_converter> p2pool_protocol;
    //TODO: typedef P2P_Protocol<c2pool::libnet::messages::c2pool_converter> c2pool_protocol;

} // namespace c2pool::p2p