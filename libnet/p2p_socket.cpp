#include "p2p_socket.h"
#include <util/messages.h>
#include <devcore/logger.h>

#include <memory>

#include <boost/asio.hpp>
#include <boost/function.hpp>
namespace ip = boost::asio::ip;

namespace c2pool::p2p
{

    P2PSocket::P2PSocket(ip::tcp::socket socket, protocol_handle const &handle) : _socket(std::move(socket))
    {
        //TODO: check p2pool/c2pool node
        shared_ptr<c2pool::p2p::Protocol> temp_protocol;
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

    void P2PSocket::write(std::shared_ptr<c2pool::messages::message> msg)
    {
        msg->send(); //TODO: rename method;
        boost::asio::async_write(_socket, boost::asio::buffer(msg->data, msg->get_length()),
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

    void P2PSocket::read_prefix()
    {
        
        tempMessage->prefix = new char[nodes->p2p_node->net()->PREFIX_LENGTH];

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

    void P2PSocket::read_command(shared_ptr<raw_message> tempRawMessage)
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

    void P2PSocket::read_length(shared_ptr<raw_message> tempRawMessage)
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

    void P2PSocket::read_checksum(shared_ptr<raw_message> tempRawMessage)
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
    void P2PSocket::read_payload(shared_ptr<raw_message> tempRawMessage)
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
} // namespace c2pool::p2p