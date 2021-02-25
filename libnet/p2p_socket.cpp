#include "p2p_socket.h"
#include "messages.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include <networks/network.h>
#include <util/pystruct.h>

#include <memory>
#include <tuple>
using std::tuple;

#include <boost/asio.hpp>
#include <boost/function.hpp>
namespace ip = boost::asio::ip;

using namespace c2pool::libnet::p2p;
using namespace c2pool::libnet::messages;

namespace c2pool::libnet::p2p
{

    P2PSocket::P2PSocket(std::shared_ptr<ip::tcp::socket> socket) : _socket(socket)
    {
        
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
        boost::asio::async_write(*_socket, boost::asio::buffer(std::get<0>(msg_data), std::get<1>(msg_data)),
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
        //make raw_message for reading data
        shared_ptr<raw_message> tempRawMessage = _protocol.lock()->make_raw_message();
        //Socket started for reading!
        read_prefix(tempRawMessage);
    }

    void P2PSocket::read_prefix(shared_ptr<raw_message> tempRawMessage)
    {
        //TODO: move to make_raw_message
        //tempMessage->prefix = new char[nodes->p2p_node->net()->PREFIX_LENGTH];
        tempRawMessage->converter->prefix = new char[100];
        //tempRawMessage->converter->
        LOG_TRACE << "read_prefix: " << tempRawMessage->converter->get_prefix_len();
        boost::asio::async_read(*_socket,
                                boost::asio::buffer(tempRawMessage->converter->prefix, 100),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    LOG_ERROR << ec.message();
                                    if (!ec && c2pool::dev::compare_str(tempRawMessage->converter->prefix, _net->PREFIX, tempRawMessage->converter->get_prefix_len()))
                                    {
                                        c2pool::python::other::debug_log(tempRawMessage->converter->prefix, _net->PREFIX_LENGTH);
                                        // LOG_INFO << "MSG: " << tempMessage->command;
                                        read_command(tempRawMessage);
                                    }
                                    else
                                    {
                                        LOG_ERROR << "read_prefix: " << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_command(shared_ptr<raw_message> tempRawMessage)
    {
        boost::asio::async_read(*_socket,
                                boost::asio::buffer(tempRawMessage->converter->command, COMMAND_LENGTH),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
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
        boost::asio::async_read(*_socket,
                                boost::asio::buffer(tempRawMessage->converter->length, PAYLOAD_LENGTH),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
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
        boost::asio::async_read(*_socket,
                                boost::asio::buffer(tempRawMessage->converter->checksum, CHECKSUM_LENGTH),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
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
        auto self(shared_from_this());
        
        boost::asio::async_read(*_socket,
                                boost::asio::buffer(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len()),
                                [this, self, tempRawMessage](boost::system::error_code ec, std::size_t length) {
                                    if (!ec)
                                    {
                                        c2pool::python::other::debug_log(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len());
                                        // LOG_INFO << "read_payload";
                                        //todo: move tempMesssage -> new message
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