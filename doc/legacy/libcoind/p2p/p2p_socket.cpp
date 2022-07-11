#include "p2p_socket.h"
#include "messages.h"
#include "p2p_protocol.h"
#include <libdevcore/types.h>
#include <libdevcore/logger.h>
#include <libdevcore/str.h>
#include <libdevcore/random.h>
#include <networks/network.h>

#include <memory>
#include <tuple>
#include <string>
using std::string;
using std::tuple;

#include <boost/asio.hpp>
#include <boost/function.hpp>
namespace ip = boost::asio::ip;

#include <networks/network.h>
#include <libcoind/data.h>
using namespace coind::p2p;
using namespace coind::p2p::messages;

namespace coind::p2p
{
    P2PSocket::P2PSocket(ip::tcp::socket socket, std::shared_ptr<coind::ParentNetwork> __parent_net) : _socket(std::move(socket)), _parent_net(__parent_net)
    {
    }

    //P2PSocket
    void P2PSocket::init(const boost::asio::ip::tcp::resolver::results_type endpoints, shared_ptr<coind::p2p::CoindProtocol> proto)
    {
        _protocol = proto;
        LOG_TRACE << "Try to connected in P2PSocket::init" << std::endl;
        boost::asio::async_connect(_socket, endpoints, [this](boost::system::error_code ec, boost::asio::ip::tcp::endpoint ep)
                                   {
                                       LOG_INFO << "Connect to " << ep.address() << ":" << ep.port();
                                       connectionMade(ep);
                                       if (!ec)
                                       {
                                           //start reading in socket:

                                           start_read();
                                       }
                                       else
                                       {
                                           LOG_ERROR << "async_connect: " << ec << " " << ec.message();
                                       }
                                   });
    }

    void P2PSocket::connectionMade(boost::asio::ip::tcp::endpoint ep)
    {
        address_type addr_to(1, ep.address().to_string(), ep.port());
        address_type addr_from(1, _socket.local_endpoint().address().to_string(), _socket.local_endpoint().port());
        auto version_msg = _protocol.lock()->make_message<message_version>(
            70017,
            1,
            c2pool::dev::timestamp(),
            addr_to,
            addr_from,
			c2pool::random::randomNonce(),
            "C2Pool:v0.1", //TODO: Network.version
            0);
        write(version_msg);
    }

    //TODO:

    // template <class protocol_type>
    // void P2PSocket::set_protocol_type_and_version(protocol_handle handle, std::shared_ptr<raw_message> raw_message_version)
    // {
    //     LOG_TRACE << "Set new protocol type!";
    //     std::shared_ptr<c2pool::libnet::p2p::Protocol> temp_protocol = std::make_shared<protocol_type>(shared_from_this(), _net);
    //     LOG_TRACE << "Called handle";
    //     LOG_TRACE << handle;
    //     if (handle.empty())
    //     {
    //         LOG_TRACE << "handle empty";
    //     }
    //     else
    //     {
    //         LOG_TRACE << "handle not empty";
    //     }

    //     LOG_TRACE << "Called handle";
    //     handle(temp_protocol); // <---------------bug there!!!!!!!!!
    //     LOG_TRACE << "Set new protocol like main!";
    //     _protocol = temp_protocol;
    //     _protocol.lock()->handle(raw_message_version);
    //     LOG_TRACE << "set_protocol_type_and_version ended!";
    // }

    void P2PSocket::write(std::shared_ptr<base_message> msg)
    {
        write_prefix(msg);
    }

    void P2PSocket::write_prefix(std::shared_ptr<base_message> msg)
    {
        boost::asio::async_write(_socket, boost::asio::buffer(_parent_net->PREFIX, _parent_net->PREFIX_LENGTH),
                                 [this, msg](boost::system::error_code _ec, std::size_t length)
                                 {
                                     if (_ec)
                                     {
                                         LOG_ERROR << "P2PSocket::write_prefix()" << _ec << ":" << _ec.message();
                                         return;
                                     }
                                     write_message_data(msg);
                                 });
    }

    struct SendPackedMsg
    {
        char *data;
        int32_t len;

        SendPackedMsg(std::shared_ptr<base_message> msg)
        {
            PackStream value;

            //command [+]
            const char *temp_cmd = coind::p2p::messages::string_coind_commands(msg->cmd);
            auto command = new char[12]{'\0'};
            memcpy(command, temp_cmd, strlen(temp_cmd));
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
            PackStream payload_checksum_stream;
            payload_checksum_stream << *msg;

            auto __checksum = coind::data::hash256(payload_checksum_stream);
            IntType(256) checksum_full(__checksum);
            PackStream _packed_checksum;
            _packed_checksum << checksum_full;
            vector<unsigned char> packed_checksum(_packed_checksum.data.end()-4, _packed_checksum.data.end());
//            std::reverse(packed_checksum.begin(), packed_checksum.end());
            PackStream checksum(packed_checksum);
            value << checksum;

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
        SendPackedMsg msg(_msg);
        boost::asio::async_write(_socket, boost::asio::buffer(msg.data, msg.len),
                                 //TODO: this -> shared_this()
                                 [this](boost::system::error_code _ec, std::size_t length)
                                 {
                                     if (_ec)
                                     {
                                         LOG_ERROR << "P2PSocket::write_message_data()" << _ec << ":" << _ec.message();
                                     }
                                 });
    }

    void P2PSocket::start_read()
    {
        LOG_TRACE << "START READING!:";
        //make raw_message for reading data
        shared_ptr<ReadPackedMsg> msg = std::make_shared<ReadPackedMsg>(_parent_net->PREFIX_LENGTH);
        LOG_TRACE << "created temp_raw_message";
        //Socket started for reading!
        read_prefix(msg);
    }

    void P2PSocket::read_prefix(shared_ptr<ReadPackedMsg> msg)
    {
        LOG_TRACE << "socket status: " << _socket.is_open();
        boost::asio::async_read(_socket,
                                boost::asio::buffer(msg->prefix, _parent_net->PREFIX_LENGTH),
                                [this, msg](boost::system::error_code ec, std::size_t length)
                                {
                                    LOG_TRACE << "try to read prefix";
                                    //TODO: compare
                                    if (!ec /*&& c2pool::dev::compare_str(tempRawMessage->converter->prefix, _net->PREFIX, tempRawMessage->converter->get_prefix_len())*/)
                                    {
                                        // LOG_INFO << "MSG: " << tempMessage->command;
                                        read_command(msg);
                                    }
                                    else
                                    {
                                        LOG_TRACE << "socket status when error in prefix: " << _socket.is_open();
                                        LOG_ERROR << "read_prefix: " << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_command(shared_ptr<ReadPackedMsg> msg)
    {
        boost::asio::async_read(_socket,
                                boost::asio::buffer(msg->command, msg->COMMAND_LEN),
                                [this, msg](boost::system::error_code ec, std::size_t /*length*/)
                                {
                                    if (!ec)
                                    {
                                        LOG_TRACE << "try to read command";
                                        read_length(msg);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_length(shared_ptr<ReadPackedMsg> msg)
    {
        boost::asio::async_read(_socket,
                                boost::asio::buffer(msg->len, msg->LEN_LEN),
                                [this, msg](boost::system::error_code ec, std::size_t /*length*/)
                                {
                                    if (!ec)
                                    {
                                        LOG_TRACE << "try to read length";
                                        read_checksum(msg);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::read_checksum(shared_ptr<ReadPackedMsg> msg)
    {
        boost::asio::async_read(_socket,
                                boost::asio::buffer(msg->checksum, msg->CHECKSUM_LEN),
                                [this, msg](boost::system::error_code ec, std::size_t /*length*/)
                                {
                                    if (!ec)
                                    {
                                        LOG_TRACE << "try to read checksum";
                                        // LOG_INFO << "read_checksum";
                                        read_payload(msg);
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }
    void P2PSocket::read_payload(shared_ptr<ReadPackedMsg> msg)
    {
        LOG_TRACE << "read_payload";
        PackStream stream_len(msg->len, msg->LEN_LEN);
        IntType(32) payload_len;
        stream_len >> payload_len;
        msg->unpacked_len = payload_len.get();

        boost::asio::async_read(_socket,
                                boost::asio::buffer(msg->payload, msg->unpacked_len),
                                [this, msg](boost::system::error_code ec, std::size_t length)
                                {
                                    if (!ec)
                                    {
                                        // LOG_INFO << "read_payload";
                                        LOG_DEBUG << "HANDLE MESSAGE!";
                                        final_read_message(msg);
                                        start_read();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void P2PSocket::final_read_message(shared_ptr<ReadPackedMsg> msg)
    {
        //checksum check
        //TODO: !!!

        //Make raw message
        PackStream stream_RawMsg;

        PackStream stream_command(msg->command, msg->COMMAND_LEN);
        PackStream stream_payload(msg->payload, msg->unpacked_len);

        stream_RawMsg << stream_command << stream_payload;

        shared_ptr<raw_message> RawMessage = _protocol.lock()->make_raw_message();
        stream_RawMsg >> *RawMessage;

        //Protocol handle message
        _protocol.lock()->handle(RawMessage);
    }
} // namespace c2pool::p2p