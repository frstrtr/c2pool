#include "p2p_socket.h"
#include "messages.h"
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

    P2PSocket::P2PSocket(ip::tcp::socket socket) : _socket(std::move(socket))
    {
        
    }

    void P2PSocket::connector_init(protocol_handle const &handle, const boost::asio::ip::tcp::resolver::results_type endpoints){
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

    void P2PSocket::init(protocol_handle const &handle){
        LOG_TRACE << "P2PSocket: " << "Start constructor";
        //TODO: check p2pool/c2pool node
        shared_ptr<Protocol> temp_protocol;

        LOG_TRACE << "P2PSocket: " << "before make_protocol";
        //if p2pool:
        //create P2P_Protocol<c2pool::libnet::messages::p2pool_converter>
        temp_protocol = make_shared<p2pool_protocol>(shared_from_this());

        LOG_TRACE << "P2PSocket: " << "temp_protocol created";
        //if c2pool:
        //create P2P_Protocol<c2pool::libnet::messages::c2pool_converter>
        //TODO: temp_protocol = make_shared<c2pool_protocol>(shared_from_this());

        //handle protocol for P2PNode
        handle(temp_protocol);

        LOG_TRACE << "P2PSocket: " << "handle call";
        //save protocol in P2PSocket like weak_ptr:
        _protocol = temp_protocol;

        //start reading in socket:
        start_read();
    }

    void P2PSocket::write(std::shared_ptr<base_message> msg)
    {
        auto msg_data = msg->serialize(); //tuple<char*, int>(data, len)
        boost::asio::async_write(_socket, boost::asio::buffer(std::get<0>(msg_data), std::get<1>(msg_data)),
                                 //TODO: this -> shared_this()
                                 [this](boost::system::error_code _ec, std::size_t length) {
                                     if (_ec)
                                     {
                                         //TODO: LOG ERROR
                                     }
                                 });
    }

    void P2PSocket::start_read()
    {
        LOG_TRACE << "START READING!:";
        //make raw_message for reading data
        LOG_TRACE << _protocol.lock().use_count();
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
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
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
                                        LOG_TRACE << "socket status when error in prefix: " <<_socket.is_open();
                                        LOG_ERROR << "read_prefix: " << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_command(shared_ptr<raw_message> tempRawMessage)
    {
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
        LOG_TRACE << tempRawMessage->converter->get_unpacked_len();
        boost::asio::async_read(_socket,
                                boost::asio::buffer(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len()),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t length) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len());
                                        // LOG_INFO << "read_payload";
                                        //todo: move tempMesssage -> new message
                                        LOG_TRACE << "HANDLE MESSAGE!";
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