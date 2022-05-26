#pragma once

#include <memory>
#include <string>
#include <iterator>
#include <algorithm>
#include <univalue.h>
#include <btclibs/uint256.h>

#include <boost/bind.hpp>

#include "messages.h"
#include "p2p_node.h"
#include "p2p_socket.h"
#include <networks/network.h>
#include <libdevcore/random.h>
#include <libdevcore/logger.h>
#include <sharechains/share.h>
#include <libdevcore/types.h>

using namespace c2pool::libnet::messages;
using std::shared_ptr, std::weak_ptr, std::make_shared;
using std::vector;

namespace c2pool::libnet::p2p
{
    class P2PNode;
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
        uint64_t other_services;
        unsigned long long _nonce;

    protected:
        shared_ptr<c2pool::libnet::p2p::P2PSocket> _socket;

    protected:
        Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> _sct);

    public:

        virtual void write(std::shared_ptr<base_message> msg)
        {
            _socket->write(msg);
        }

        virtual void handle(shared_ptr<raw_message> RawMSG)
        {}

        virtual shared_ptr<raw_message> make_raw_message(std::string cmd)
        { return make_shared<raw_message>(cmd); }
    };

    class P2P_Protocol : public Protocol, public enable_shared_from_this<P2P_Protocol>
    {
    private:
        std::shared_ptr<c2pool::Network> _net;
        std::shared_ptr<libnet::p2p::P2PNode> _p2p_node;

        std::set<uint256> remote_tx_hashes;
        int32_t remote_remembered_txs_size = 0;

        std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
        int32_t remembered_txs_size;
        std::vector<std::map<uint256, coind::data::tx_type>> known_txs_cache;

    public:
        P2P_Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket, std::shared_ptr<c2pool::Network> __net,
                     std::shared_ptr<libnet::p2p::P2PNode> __p2p_node);

        void refresh_autodisconnect_timer()
        {
            _socket->auto_disconnect_timer.expires_from_now(boost::asio::chrono::seconds(100));
            _socket->auto_disconnect_timer.async_wait([&](const boost::system::error_code &ec)
                                                      {
                                                          if (!ec)
                                                          {
                                                              _socket->disconnect();
                                                              LOG_INFO << "Auto disconnect, peer: "
                                                                       << std::get<0>(_socket->get_addr()) << ":"
                                                                       << std::get<1>(_socket->get_addr());
                                                          }
                                                      });
        }

        void handle(shared_ptr<raw_message> RawMSG) override
        {
            LOG_DEBUG << "called HANDLE msg in p2p_protocol" << ", with name_type = " << RawMSG->command;
            switch (reverse_string_commands(RawMSG->command.c_str()))
            {
                case commands::cmd_version:
                    handle(GenerateMsg<message_version>(RawMSG->value));
                    break;
                case commands::cmd_ping:
                    handle(GenerateMsg<message_ping>(RawMSG->value));
                    break;
                case commands::cmd_addrme:
                    handle(GenerateMsg<message_addrme>(RawMSG->value));
                    break;
                case commands::cmd_addrs:
                    handle(GenerateMsg<message_addrs>(RawMSG->value));
                    break;
                case commands::cmd_getaddrs:
                    handle(GenerateMsg<message_getaddrs>(RawMSG->value));
                    break;
                    //new:
                case commands::cmd_shares:
                    handle(GenerateMsg<message_shares>(RawMSG->value));
                    break;
                case commands::cmd_sharereq:
                    handle(GenerateMsg<message_sharereq>(RawMSG->value));
                    break;
                case commands::cmd_sharereply:
                    handle(GenerateMsg<message_sharereply>(RawMSG->value));
                    break;
                    //TODO:
                    // case commands::cmd_best_block:
                    //     handle(GenerateMsg<message_best_block>(RawMSG->value));
                    //     break;
                case commands::cmd_have_tx:
                    handle(GenerateMsg<message_have_tx>(RawMSG->value));
                    break;
                case commands::cmd_losing_tx:
                    handle(GenerateMsg<message_losing_tx>(RawMSG->value));
                    break;
                case commands::cmd_forget_tx:
                    handle(GenerateMsg<message_forget_tx>(RawMSG->value));
                    break;
                case commands::cmd_remember_tx:
                    handle(GenerateMsg<message_remember_tx>(RawMSG->value));
                    break;
                case commands::cmd_error:
                    //TODO: fix
                    handle(GenerateMsg<message_error>(RawMSG->value));
                    break;
            }
            refresh_autodisconnect_timer();
        }

        template<class message_type, class... Args>
        shared_ptr<message_type> make_message(Args &&...args)
        {
            auto msg = std::make_shared<message_type>(args...);
            return msg;
        }

    protected:
        template<class MsgType>
        //template <class MsgType<>, class ct = converter_type>
        shared_ptr<MsgType> GenerateMsg(PackStream &stream)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            stream >> *msg;
            return msg;
        }

        void ping_timer_func(const boost::system::error_code &ec)
        {
            int _time = (int) c2pool::random::Expovariate(100);
            //LOG_TRACE << "TIME FROM EXPOVARIATE: " << _time;
            _socket->ping_timer.expires_from_now(boost::asio::chrono::seconds(_time));
            _socket->ping_timer.async_wait(boost::bind(&P2P_Protocol::ping_timer_func, this, _1));

            auto msg = make_message<message_ping>();
            write(msg);
        }

        void handle(shared_ptr<message_version> msg);

        void handle(shared_ptr<message_addrs> msg);

        //TODO: test:
        void handle(shared_ptr<message_addrme> msg);

        void handle(shared_ptr<message_ping> msg);

        //TODO: TEST
        void handle(shared_ptr<message_getaddrs> msg);

        void handle(shared_ptr<message_error> msg);

        void handle(shared_ptr<message_shares> msg);

        void handle(shared_ptr<message_sharereq> msg);

        void handle(shared_ptr<message_sharereply> msg);

        void handle(shared_ptr<message_bestblock> msg);

        void handle(shared_ptr<message_have_tx> msg);

        void handle(shared_ptr<message_losing_tx> msg);

        void handle(shared_ptr<message_remember_tx> msg);

        void handle(shared_ptr<message_forget_tx> msg);
    };
} // namespace c2pool::p2p