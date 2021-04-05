#pragma once

#include "messages.h"
#include "converter.h"
#include <devcore/logger.h>
#include "p2p_socket.h"
using namespace c2pool::coind::p2p::messages;

#include <univalue.h>
#include <btclibs/uint256.h>

#include <memory>
using std::shared_ptr, std::weak_ptr, std::make_shared;

namespace c2pool::coind::p2p
{
    class P2PSocket;
}

namespace c2pool::coind::p2p
{
    //https://en.bitcoin.it/wiki/Protocol_documentation
    class CoindProtocol
    {
    public:
    protected:
        shared_ptr<c2pool::coind::p2p::P2PSocket> _socket;
        std::shared_ptr<c2pool::Network> _net; //TODO: parent network

    protected:
        CoindProtocol(shared_ptr<c2pool::coind::p2p::P2PSocket> _sct, std::shared_ptr<c2pool::Network> _network);

    public:
        shared_ptr<raw_message> make_raw_message()
        {
            auto raw_msg = make_shared<raw_message>();
            raw_msg->set_prefix(_net);
            return raw_msg;
        }

        //----------------------------------------------------------------------------

        void handle(shared_ptr<raw_message> RawMSG)
        {
            LOG_DEBUG << "called HANDLE msg in p2p_protocol";
            //В Python скрипте, команда передается, как int, эквивалентный commands
            RawMSG->deserialize();
            LOG_TRACE << "rawmsg value = " << RawMSG->value.isNull();
            LOG_TRACE << "RawMSG->value: " << RawMSG->value.write();
            UniValue json_value = RawMSG->value;

            switch (RawMSG->name_type) //todo: switch -> if (" " == cmd)
            {
            case commands::cmd_version:
                handle(GenerateMsg<message_version>(json_value));
                break;
            case commands::cmd_verack:
                handle(GenerateMsg<message_verack>(json_value));
                break;
            case commands::cmd_ping:
                handle(GenerateMsg<message_ping>(json_value));
                break;
            case commands::cmd_pong:
                handle(GenerateMsg<message_pong>(json_value));
                break;
            case commands::cmd_alert:
                handle(GenerateMsg<message_alert>(json_value));
                break;
            case commands::cmd_getaddr:
                handle(GenerateMsg<message_getaddr>(json_value));
                break;
            case commands::cmd_addr:
                handle(GenerateMsg<message_addr>(json_value));
                break;
            case commands::cmd_inv:
                handle(GenerateMsg<message_inv>(json_value));
                break;
            case commands::cmd_getdata:
                handle(GenerateMsg<message_getdata>(json_value));
                break;
            case commands::cmd_reject:
                handle(GenerateMsg<message_reject>(json_value));
                break;
            case commands::cmd_getblocks:
                handle(GenerateMsg<message_getblocks>(json_value));
                break;
            case commands::cmd_getheaders:
                handle(GenerateMsg<message_getheaders>(json_value));
                break;
            case commands::cmd_tx:
                handle(GenerateMsg<message_tx>(json_value));
                break;
            case commands::cmd_block:
                handle(GenerateMsg<message_block>(json_value));
                break;
            case commands::cmd_headers:
                handle(GenerateMsg<message_headers>(json_value));
                break;
            case commands::cmd_error:
                handle(GenerateMsg<message_error>(json_value));
                break;
            }
        }

        template <class message_type, class... Args>
        shared_ptr<message_type> make_message(Args &&...args)
        {
            auto msg = std::make_shared<message_type>(args...);
            msg->set_prefix(_net);
            return msg;
        }

    protected:
        template <class MsgType>
        shared_ptr<MsgType> GenerateMsg(UniValue &value)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            *msg = value;
            return msg;
        }

        void handle(shared_ptr<message_version> msg)
        {
        }

        void handle(shared_ptr<message_verack> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_ping> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_pong> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_alert> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_getaddr> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_addr> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_inv> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_getdata> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_reject> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_getblocks> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_getheaders> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_tx> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_block> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_headers> msg)
        {
            //TODO:
        }

        void handle(shared_ptr<message_error> msg)
        {
            LOG_WARNING << "Handled message_error! command = " << msg->command << " ; error_text = " << msg->error_text;
        }
    };
} // namespace c2pool::p2p