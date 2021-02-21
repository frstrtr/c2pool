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

using namespace c2pool::p2p;
using namespace c2pool::libnet::messages;

namespace c2pool::libnet::p2p
{

    P2PSocket::P2PSocket(ip::tcp::socket socket, protocol_handle const &handle) : _socket(std::move(socket))
    {
        //TODO: check p2pool/c2pool node
        shared_ptr<Protocol> temp_protocol;
        //if p2pool:
        //create P2P_Protocol<c2pool::libnet::messages::p2pool_converter>
        temp_protocol = make_shared<p2pool_protocol>(shared_from_this());

        //if c2pool:
        //create P2P_Protocol<c2pool::libnet::messages::c2pool_converter>
        //TODO: temp_protocol = make_shared<c2pool_protocol>(shared_from_this());

        //handle protocol for P2PNode
        handle(temp_protocol);

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
        //make raw_message for reading data
        shared_ptr<raw_message> tempRawMessage = _protocol.lock()->make_raw_message();
        //Socket started for reading!
        read_prefix(tempRawMessage);
    }

    void P2PSocket::read_prefix(shared_ptr<raw_message> tempRawMessage)
    {
        //TODO: move to make_raw_message
        //tempMessage->prefix = new char[nodes->p2p_node->net()->PREFIX_LENGTH];

        boost::asio::async_read(socket,
                                boost::asio::buffer(tempRawMessage->converter->prefix, tempRawMessage->converter->get_prefix_len()),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec && c2pool::dev::compare_str(tempRawMessage->converter->prefix, _net->PREFIX, tempRawMessage->converter->get_prefix_len()))
                                    {
                                        c2pool::python::other::debug_log(tempRawMessage->converter->prefix, _net->PREFIX_LENGTH);
                                        // LOG_INFO << "MSG: " << tempMessage->command;
                                        read_command(tempRawMessage);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_command(shared_ptr<raw_message> tempRawMessage)
    {
        boost::asio::async_read(socket,
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
        boost::asio::async_read(socket,
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
        boost::asio::async_read(socket,
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
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempRawMessage->converter->payload, tempRawMessage->converter->get_unpacked_len()),
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/) {
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