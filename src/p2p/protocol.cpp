#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
using boost::asio::ip::tcp;

#include "protocol.h"
#include "factory.h"
#include "node.h"
#include "console.h"
#include "messages.h"
#include "pystruct.h"
#include "other.h"

//-----------------------------------------------------------

class Node;
namespace c2pool::messages
{
    class message;
}
//-----------------------------------------------------------

namespace c2pool::p2p
{

    //Protocol
    Protocol::Protocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory) : socket(std::move(_socket)), version(3301)
    {
        factory = _factory;
        nodes = factory->getNode(); //TODO: изменить на NodeManager
        //addr;
    }

    // //msg.data(), msg.length()
    // void Protocol::write(unique_ptr<c2pool::messages::message> msg)
    // {
    //     boost::asio::async_write(socket,
    //                              boost::asio::buffer(msg->data, msg->get_length()),
    //                              [this](boost::system::error_code ec, std::size_t /*length*/) {
    //                                  if (!ec)
    //                                  {
    //                                  }
    //                                  else
    //                                  {
    //                                      disconnect();
    //                                  }
    //                              });
    // }

    void Protocol::read_prefix()
    {
        tempMessage = std::make_unique<c2pool::messages::IMessage>(/*TODO: net.PREFIX*/);
        tempMessage->prefix = new char[nodes->p2p_node->net()->PREFIX_LENGTH];
        //char* temp;

        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->prefix, nodes->p2p_node->net()->PREFIX_LENGTH),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec && c2pool::str::compare_str(tempMessage->prefix, nodes->p2p_node->net()->PREFIX, nodes->p2p_node->net()->PREFIX_LENGTH))
                                    {
                                        c2pool::python::other::debug_log(tempMessage->prefix, nodes->p2p_node->net()->PREFIX_LENGTH);
                                        // LOG_INFO << "MSG: " << tempMessage->command;
                                        read_command();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_command()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->command, tempMessage->command_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempMessage->command, tempMessage->command_length);
                                        //LOG_INFO << "read_command";
                                        read_length();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_length()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->length, tempMessage->payload_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempMessage->length, tempMessage->payload_length);
                                        tempMessage->set_unpacked_length();
                                        // LOG_INFO << "read_length";
                                        read_checksum();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_checksum()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->checksum, tempMessage->checksum_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempMessage->checksum, tempMessage->checksum_length);
                                        // LOG_INFO << "read_checksum";
                                        read_payload();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_payload()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->payload, tempMessage->unpacked_length()),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempMessage->payload, tempMessage->unpacked_length());
                                        // LOG_INFO << "read_payload";
                                        //todo: move tempMesssage -> new message
                                        read_prefix();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::disconnect()
    {
        boost::asio::post(factory->io_context, [this]() { socket.close(); });
    }

    void Protocol::send(c2pool::messages::message *msg)
    {
        msg->send();
        boost::asio::async_write(socket,
                                 boost::asio::buffer(msg->data, msg->get_length()),
                                 [this](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec)
                                     {
                                        //
                                     }
                                     else
                                     {
                                        LOG_ERROR << ec;
                                        disconnect();
                                     }
                                 });
    }

    //OLD: fromStr
    void Protocol::handle(UniValue &value)
    {
        //В Python скрипте, команда передается, как int, эквивалентный c2pool::messages::commands
        int cmd;
        cmd = value["name_type"].get_int();
        c2pool::messages::message *res;

        auto json = value["value"].get_obj();

        switch (cmd) //todo: switch -> if (" " == cmd)
        {
        case c2pool::messages::commands::cmd_addrs:
            handle(GenerateMsg<c2pool::messages::message_addrs>(json));
            break;
        case c2pool::messages::commands::cmd_version:
            handle(GenerateMsg<c2pool::messages::message_version>(json));
            break;
        case c2pool::messages::commands::cmd_ping:
            handle(GenerateMsg<c2pool::messages::message_ping>(json));
            break;
        case c2pool::messages::commands::cmd_addrme:
            handle(GenerateMsg<c2pool::messages::message_addrme>(json));
            break;
        case c2pool::messages::commands::cmd_getaddrs:
            handle(GenerateMsg<c2pool::messages::message_getaddrs>(json));
            break;
        //new:
        case c2pool::messages::commands::cmd_shares:
            handle(GenerateMsg<c2pool::messages::message_shares>(json));
            break;
        case c2pool::messages::commands::cmd_sharereq:
            handle(GenerateMsg<c2pool::messages::message_sharereq>(json));
            break;
        case c2pool::messages::commands::cmd_sharereply:
            handle(GenerateMsg<c2pool::messages::message_sharereply>(json));
            break;
        //TODO:
        // case c2pool::messages::commands::cmd_best_block:
        //     handle(GenerateMsg<c2pool::messages::message_best_block>(json));
        //     break;
        case c2pool::messages::commands::cmd_have_tx:
            handle(GenerateMsg<c2pool::messages::message_have_tx>(json));
            break;
        case c2pool::messages::commands::cmd_losing_tx:
            handle(GenerateMsg<c2pool::messages::message_losing_tx>(json));
            break;
        default:
            handle(GenerateMsg<c2pool::messages::message_error>(json));
            break;
        }
    }

    template <class MsgType>
    MsgType *Protocol::GenerateMsg(UniValue &value)
    {
        MsgType *msg = new MsgType();
        *msg = value;
        return msg;
    }

    void Protocol::handle(c2pool::messages::message_version *msg)
    {

        std::cout << "Peer " << msg->addr_from.address << ":" << msg->addr_from.port << " says protocol version is " << msg->version << ", client version " << msg->sub_version; //TODO: to Log system

        if (other_version != -1)
        {
            //TODO: DEBUG: raise PeerMisbehavingError('more than one version message')
        }
        if (msg->version < nodes->p2p_node->net()->MINIMUM_PROTOCOL_VERSION)
        {
            //TODO: DEBUG: raise PeerMisbehavingError('peer too old')
        }

        other_version = msg->version;
        other_sub_version = msg->sub_version;
        other_services = msg->services;

        if (msg->nonce == nodes->p2p_node->nonce) //TODO: add nonce in Node
        {
            //TODO: DEBUG: raise PeerMisbehavingError('was connected to self')
        }

        //detect duplicate in node->peers
        for (auto _peer : nodes->p2p_node->peers)
        {
            if (_peer.first == msg->nonce)
            {
                LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":" << std::get<1>(addr);
                disconnect();
                return;
            }
        }

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

        factory->protocol_connected(shared_from_this());

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
    }

    void Protocol::handle(c2pool::messages::message_addrs *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_addrme *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_ping *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_getaddrs *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_error *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_shares *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_sharereq *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_sharereply *msg)
    {
        //TODO:
    }

    //TODO:
    // void Protocol::handle(c2pool::messages::message_best_block *msg)
    // {
    // }

    void Protocol::handle(c2pool::messages::message_have_tx *msg)
    {
        //TODO:
    }

    void Protocol::handle(c2pool::messages::message_losing_tx *msg)
    {
        //TODO:
    }

    void Protocol::update_addr()
    {
        boost::asio::ip::tcp::endpoint ep = socket.remote_endpoint();

        addr = std::make_tuple(ep.address().to_string(), std::to_string(ep.port()));
    }

    //ClientProtocol
    ClientProtocol::ClientProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory, const boost::asio::ip::tcp::resolver::results_type endpoints) : Protocol(std::move(_socket), _factory)
    {
        LOG_INFO << "ClientProtocol created.";
        do_connect(endpoints);
    }

    void ClientProtocol::do_connect(const boost::asio::ip::tcp::resolver::results_type endpoints)
    {
        boost::asio::async_connect(socket, endpoints, [this](boost::system::error_code ec, tcp::endpoint) {
            update_addr();
            LOG_INFO << "Connect to " << std::get<0>(addr) << ":" << std::get<1>(addr);
            if (!ec)
            {
                // c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
                // c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
                // c2pool::messages::message* firstMsg = new c2pool::messages::message_version(version, 0, addrs1, addrs2, nodes->p2p_node->nonce, "16", 1, 18);
                // send(firstMsg);
                read_prefix();
            } else {
                LOG_ERROR << ec;
            }
        });
    }

    //ServerProtocol
    ServerProtocol::ServerProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory) : Protocol(std::move(_socket), _factory)
    {
        LOG_INFO << "ServerProtocol created.";
        start();
    }

    void ServerProtocol::start()
    {
        update_addr();
        read_prefix();
    }
} // namespace c2pool::p2p