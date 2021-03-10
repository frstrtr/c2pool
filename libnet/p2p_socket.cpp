#include "p2p_socket.h"
#include "messages.h"
#include "p2p_protocol.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include <networks/network.h>
#include <util/pystruct.h>

#include <memory>
#include <tuple>
#include <string>
using std::string;
using std::tuple;

#include <boost/asio.hpp>
#include <boost/function.hpp>
namespace ip = boost::asio::ip;

using namespace c2pool::libnet::p2p;
using namespace c2pool::libnet::messages;

namespace c2pool::libnet::p2p
{
    //P2PSocket

    P2PSocket::P2PSocket(ip::tcp::socket socket, shared_ptr<c2pool::Network> _network) : _socket(std::move(socket)), _net(_network)
    {
    }

    void P2PSocket::connector_init(protocol_handle handle, const boost::asio::ip::tcp::resolver::results_type endpoints)
    {
        //auto self = shared_from_this();
        boost::asio::async_connect(_socket, endpoints, [this, handle](boost::system::error_code ec, boost::asio::ip::tcp::endpoint ep) {
            LOG_INFO << "Connect to " << ep.address() << ":" << ep.port();
            if (!ec)
            {
                // c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
                // c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
                // c2pool::messages::message* firstMsg = new c2pool::messages::message_version(version, 0, addrs1, addrs2, nodes->p2p_node->nonce, "16", 1, 18);
                // send(firstMsg);
                init(handle);
            }
            else
            {
                LOG_ERROR << "async_connect: " << ec << " " << ec.message();
            }
        });
    }

    void P2PSocket::init(protocol_handle handle)
    {
        LOG_TRACE << "P2PSocket: "
                  << "Start constructor";

        //if p2pool:
        //create P2P_Protocol<c2pool::libnet::messages::p2pool_converter>
        initialize_protocol = std::make_shared<initialize_network_protocol>(shared_from_this(), handle, _net);

        //if c2pool:
        //create P2P_Protocol<c2pool::libnet::messages::c2pool_converter>
        //TODO: temp_protocol = make_shared<c2pool_protocol>(shared_from_this());

        _protocol = initialize_protocol;

        //start reading in socket:
        start_read();
    }

    template <class protocol_type>
    void P2PSocket::set_protocol_type_and_version(protocol_handle handle, std::shared_ptr<raw_message> raw_message_version)
    {
        LOG_TRACE << "Set new protocol type!";
        std::shared_ptr<c2pool::libnet::p2p::Protocol> temp_protocol = std::make_shared<protocol_type>(shared_from_this(), _net);
        LOG_TRACE << "Called handle";
        LOG_TRACE << handle;
        if (handle.empty())
        {
            LOG_TRACE << "handle empty";
        } else {
            LOG_TRACE << "handle not empty";
        }

        LOG_TRACE << "Called handle";
        handle(temp_protocol); // <---------------bug there!!!!!!!!!
        LOG_TRACE << "Set new protocol like main!";
        _protocol = temp_protocol;
        _protocol.lock()->handle(raw_message_version);
        LOG_TRACE << "set_protocol_type_and_version ended!";
    }

    template void P2PSocket::set_protocol_type_and_version<p2pool_protocol>(protocol_handle handle, std::shared_ptr<raw_message> raw_message_version);

    void P2PSocket::write(std::shared_ptr<base_message> msg)
    {
        //TODO-----------------------------------<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>
        //['83', 'e6', '5d', '2c', '81', 'bf', '6d', '68'] PREFIX insert
        auto msg_data = msg->serialize(); //tuple<char*, int>(data, len)
        boost::asio::async_write(_socket, boost::asio::buffer(std::get<0>(msg_data), std::get<1>(msg_data)),
                                 //TODO: this -> shared_this()
                                 [this](boost::system::error_code _ec, std::size_t length) {
                                     if (_ec)
                                     {
                                         LOG_ERROR << "P2PSocket::write()" << _ec << ":" << _ec.message();
                                     }
                                 });
    }

    void P2PSocket::start_read()
    {
        LOG_TRACE << "START READING!:";
        //make raw_message for reading data
        LOG_TRACE << "protocol count" << _protocol.lock().use_count();
        shared_ptr<raw_message> tempRawMessage = _protocol.lock()->make_raw_message();
        LOG_TRACE << "created temp_raw_message";
        //Socket started for reading!
        read_prefix(tempRawMessage);
    }

    void P2PSocket::read_prefix(shared_ptr<raw_message> tempRawMessage)
    {
        //TODO: move to make_raw_message
        //tempMessage->prefix = new char[nodes->p2p_node->net()->PREFIX_LENGTH];
        tempRawMessage->converter->prefix = new char[8];
        LOG_TRACE << "socket status: " << _socket.is_open();
        boost::asio::async_read(_socket,
                                boost::asio::buffer(tempRawMessage->converter->prefix, 8),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t length) {
                                    LOG_TRACE << "try to read prefix";
                                    if (!ec /*&& c2pool::dev::compare_str(tempRawMessage->converter->prefix, _net->PREFIX, tempRawMessage->converter->get_prefix_len())*/)
                                    {
                                        LOG_TRACE << "compare prefix";
                                        //c2pool::python::other::debug_log(tempRawMessage->converter->prefix, _net->PREFIX_LENGTH);
                                        LOG_TRACE << "after debug_log";
                                        // LOG_INFO << "MSG: " << tempMessage->command;
                                        read_command(tempRawMessage);
                                    }
                                    else
                                    {
                                        LOG_TRACE << tempRawMessage->converter->prefix;
                                        LOG_TRACE << "read_prefix: " << length;
                                        LOG_TRACE << "socket status when error in prefix: " << _socket.is_open();
                                        LOG_ERROR << "read_prefix: " << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_command(shared_ptr<raw_message> tempRawMessage)
    {
        LOG_TRACE << "protocol count in read_command" << _protocol.lock().use_count();
        boost::asio::async_read(_socket,
                                boost::asio::buffer(tempRawMessage->converter->command, COMMAND_LENGTH),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_TRACE << "try to read command";
                                        c2pool::python::other::debug_log(tempRawMessage->converter->command, COMMAND_LENGTH);
                                        //LOG_INFO << "read_command";
                                        read_length(tempRawMessage);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_length(shared_ptr<raw_message> tempRawMessage)
    {
        boost::asio::async_read(_socket,
                                boost::asio::buffer(tempRawMessage->converter->length, PAYLOAD_LENGTH),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_TRACE << "try to read length";
                                        c2pool::python::other::debug_log(tempRawMessage->converter->length, PAYLOAD_LENGTH);
                                        tempRawMessage->converter->set_unpacked_len();
                                        // LOG_INFO << "read_length";
                                        read_checksum(tempRawMessage);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_checksum(shared_ptr<raw_message> tempRawMessage)
    {
        boost::asio::async_read(_socket,
                                boost::asio::buffer(tempRawMessage->converter->checksum, CHECKSUM_LENGTH),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_TRACE << "try to read checksum";
                                        c2pool::python::other::debug_log(tempRawMessage->converter->checksum, CHECKSUM_LENGTH);
                                        // LOG_INFO << "read_checksum";
                                        read_payload(tempRawMessage);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }
    void P2PSocket::read_payload(shared_ptr<raw_message> tempRawMessage)
    {
        LOG_TRACE << "read_payload";
        boost::asio::async_read(_socket,
                                boost::asio::buffer(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len()),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t length) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len());
                                        // LOG_INFO << "read_payload";
                                        LOG_DEBUG << "HANDLE MESSAGE!";
                                        _protocol.lock()->handle(tempRawMessage);
                                        start_read();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }
} // namespace c2pool::p2p