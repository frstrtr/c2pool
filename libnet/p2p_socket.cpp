#include "p2p_socket.h"
#include "messages.h"
#include "p2p_protocol.h"
#include "p2p_node.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include <networks/network.h>
#include <util/pystruct.h>
#include <util/stream.h>
#include <util/stream_types.h>

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

    P2PSocket::P2PSocket(ip::tcp::socket socket, const c2pool::libnet::INodeMember &member) : _socket(std::move(socket)), c2pool::libnet::INodeMember(member)
    {
    }

    void P2PSocket::connector_init(protocol_handle handle, const boost::asio::ip::tcp::resolver::results_type endpoints)
    {
        //auto self = shared_from_this();
        boost::asio::async_connect(_socket, endpoints, [this, handle](boost::system::error_code ec, boost::asio::ip::tcp::endpoint ep)
                                   {
                                       LOG_INFO << "Connect to " << ep.address() << ":" << ep.port();
                                       if (!ec)
                                       {
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

        auto proto = std::make_shared<c2pool::libnet::p2p::P2P_Protocol>(shared_from_this(), this);

        if (handle.empty())
        {
            LOG_TRACE << "handle empty";
        }
        else
        {
            LOG_TRACE << "handle not empty";
        }
        LOG_TRACE << "Called handle";
        handle(proto); // <---------------bug there!!!!!!!!!?????

        _protocol = proto;
        //start reading in socket:
        start_read();
    }

    void P2PSocket::write(std::shared_ptr<base_message> msg)
    {
        // auto msg_data = std::make_shared<StreamMessageData>(msg, net());
        write_prefix(msg);
    }

    void P2PSocket::write_prefix(std::shared_ptr<base_message> msg)
    {
        boost::asio::async_write(_socket, boost::asio::buffer(net()->PREFIX, net()->PREFIX_LENGTH),
                                 [this, msg](boost::system::error_code _ec, std::size_t length)
                                 {
                                     if (_ec)
                                     {
                                         LOG_ERROR << "P2PSocket::write()" << _ec << ":" << _ec.message();
                                         return;
                                     }
                                     write_message_data(msg);
                                 });
    }

    struct SendPackedMsg
    {

        char *data;
        int32_t len;

        SendPackedMsg(std::shared_prt<base_message> msg)
        {
            PackStream value;

            //command [+]
            const char *temp_cmd = c2pool::libnet::messages::string_commands(msg->cmd);
            auto command = new char[12]{'\0'};
            memcpy(command, temp_cmp, strlen(temp_cmd));
            PackStream s_command(command, 12);
            value << s_command;
            delete command;

            //-----
            PackStream payload_stream;
            payload_stream << *msg;

            //len [+]
            IntType(32) unpacked_len(payload_stream.size());
            value << unpacked_len;

            //checksum [-]
            //TODO: sha256(sha256(payload))

            //payload [+]
            value << payload_stream;

            //result
            data = new char[value.size()];
            memcpy(data, value.bytes(), value.size());
            len = value.size();
        }

        ~SendPackedMsg()
        {
            if (data != nullptr)
            {
                delete data;
            }
        }
    };

    void P2PSocket::write_message_data(std::shared_ptr<base_message> _msg)
    {
        SendPackedMsg msg(msg);
        boost::asio::async_write(_socket, boost::asio::buffer(msg.data, msg.len),
                                 //TODO: this -> shared_this()
                                 [this](boost::system::error_code _ec, std::size_t length)
                                 {
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
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t length)
                                {
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
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/)
                                {
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
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/)
                                {
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
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t /*length*/)
                                {
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
                                [this, tempRawMessage](boost::system::error_code ec, std::size_t length)
                                {
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