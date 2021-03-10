#pragma once

#include "messages.h"
#include "converter.h"
#include <devcore/logger.h>
#include "p2p_socket.h"
using namespace c2pool::libnet::messages;

#include <lib/univalue/include/univalue.h>
#include <btclibs/uint256.h>

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
    public:
        const int version;

        unsigned int other_version = -1;
        std::string other_sub_version;
        int other_services; //TODO: int64? IntType(64)
        unsigned long long _nonce;

    protected:
        shared_ptr<c2pool::libnet::p2p::P2PSocket> _socket;
        std::shared_ptr<c2pool::Network> _net;

    protected:
        Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> _sct, std::shared_ptr<c2pool::Network> _network);

    public:
        virtual void handle(shared_ptr<raw_message> RawMSG) {}

        virtual shared_ptr<raw_message> make_raw_message() { return make_shared<raw_message>(); }
    };

    //protocol for init network type [c2pool/p2pool]; user only for messave_version
    class initialize_network_protocol : public Protocol, public std::enable_shared_from_this<initialize_network_protocol>
    {
    private:
        protocol_handle _handle;

        //true = c2pool; false = p2pool
        bool check_c2pool(UniValue &raw_message_version_json)
        {
            //todo
            return false;
        }

    public:
        initialize_network_protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket, protocol_handle handle_obj, std::shared_ptr<c2pool::Network> _network) : Protocol(socket, _network), _handle(std::move(handle_obj))
        {
        }

        void handle(shared_ptr<raw_message> RawMSG_version) override;

        shared_ptr<raw_message> make_raw_message() override
        {
            auto raw_msg = make_shared<raw_message>();
            raw_msg->set_converter_type<p2pool_converter>();
            raw_msg->set_prefix(_net);
            return raw_msg;
        }
    };

    template <class converter_type>
    class P2P_Protocol : public Protocol
    {
    public:
        //TODO: constructor (shared_ptr<initialize_network_protocol>)
        P2P_Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket, shared_ptr<c2pool::Network> _network) : Protocol(socket, _network)
        {
            LOG_TRACE << "P2P_Protcol: "
                      << "start constructor";
        }

        void handle(shared_ptr<raw_message> RawMSG) override
        {
            LOG_DEBUG << "called HANDLE msg in p2p_protocol";
            //В Python скрипте, команда передается, как int, эквивалентный commands
            RawMSG->deserialize();
            LOG_TRACE << "rawmsg value = " << RawMSG->value.isNull();
            LOG_TRACE << "RawMSG->value: " << RawMSG->value.write();
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
            raw_msg->set_prefix(_net);
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
            LOG_DEBUG << "handle message_version";

            LOG_TRACE << msg->best_share_hash.GetHex();

            //--------
            LOG_INFO << "Peer " << msg->addr_from.address << ":" << msg->addr_from.port << " says protocol version is " << msg->version << ", client version " << msg->sub_version;

            if (other_version != -1)
            {
                //TODO: DEBUG: raise PeerMisbehavingError('more than one version message')
            }
            //TODO; if (msg->version < nodes->p2p_node->net()->MINIMUM_PROTOCOL_VERSION)
            {
                //TODO: DEBUG: raise PeerMisbehavingError('peer too old')
            }

            other_version = msg->version;
            other_sub_version = msg->sub_version;
            other_services = msg->services;

            //TODO: if (msg->nonce == nodes->p2p_node->nonce) //TODO: add nonce in Node
            {
                //TODO: DEBUG: raise PeerMisbehavingError('was connected to self')
            }

            //detect duplicate in node->peers
            // for (auto _peer : nodes->p2p_node->peers)
            // {
            //     if (_peer.first == msg->nonce)
            //     {
            //         LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":" << std::get<1>(addr);
            //         disconnect();
            //         return;
            //     }
            // }

            _nonce = msg->nonce;
            //connected2 = true; //?

            //TODO: safe thrade cancel
            //todo: timeout_delayed.cancel();
            //timeout_delayed = new boost::asio::steady_timer(io, boost::asio::chrono::seconds(100)); //todo: timer io from constructor
            //todo: timeout_delayed.async_wait(boost::bind(_timeout, boost::asio::placeholders::error)); //todo: thread
            //_____________

            /* TODO: TIMER + DELEGATE
             old_dataReceived = self.dataReceived
        def new_dataReceived(data):
            if self.timeout_delayed is not None:
                self.timeout_delayed.reset(100)
            old_dataReceived(data)
        self.dataReceived = new_dataReceived
             */

            // factory->protocol_connected(shared_from_this());

            /* TODO: thread (coroutine?):
             self._stop_thread = deferral.run_repeatedly(lambda: [
            self.send_ping(),
        random.expovariate(1/100)][-1])

             if self.node.advertise_ip:
            self._stop_thread2 = deferral.run_repeatedly(lambda: [
                self.sendAdvertisement(),
            random.expovariate(1/(100*len(self.node.peers) + 1))][-1])
             */

            //best_hash = 0 default?
            // if (best_hash != -1)
            // {                                                 // -1 = None
            //     node->handle_share_hashes([best_hash], this); //TODO: best_share_hash in []?
            // }
            //--------

            // message_version* msg = new message_version()
            int ver = version;
            std::string test_sub_ver = "16";
            unsigned long long test_nonce = 6535423;
            c2pool::util::messages::address_type addrs1(3, "4.5.6.7", 8);
            c2pool::util::messages::address_type addrs2(9, "10.11.12.13", 14);
            uint256 best_hash_test_answer;
            best_hash_test_answer.SetHex("0123");
            shared_ptr<message_version> answer_msg = std::make_shared<message_version>(ver, 0, addrs1, addrs2, test_nonce, test_sub_ver, 18, best_hash_test_answer);
            LOG_TRACE << "set converter type for answer msg";
            answer_msg->set_converter_type<converter_type>();
            LOG_TRACE << "write answer msg for socket";
            _socket->write(answer_msg);
            // _socket->write()
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