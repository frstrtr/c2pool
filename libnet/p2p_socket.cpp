#include "p2p_socket.h"

#include <memory>
#include <tuple>
#include <string>

#include <boost/asio.hpp>
#include <boost/function.hpp>

#include "messages.h"
#include "p2p_protocol.h"
#include "p2p_node.h"
#include <libdevcore/logger.h>
#include <libdevcore/str.h>
#include <networks/network.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>
#include <libcoind/data.h>

using std::string;
using std::tuple;
namespace ip = boost::asio::ip;
using namespace c2pool::libnet::p2p;
using namespace c2pool::libnet::messages;

namespace c2pool::libnet::p2p
{
    //P2PSocket

    P2PSocket::P2PSocket(ip::tcp::socket socket, std::shared_ptr<c2pool::Network> __net, std::shared_ptr<libnet::p2p::P2PNode> __p2p_node) : _socket(std::move(socket)), _net(__net), _p2p_node(__p2p_node)
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

        auto proto = std::make_shared<c2pool::libnet::p2p::P2P_Protocol>(shared_from_this(), _net, _p2p_node);

        if (handle.empty())
        {
            LOG_TRACE << "handle empty";
        }
        else
        {
            LOG_TRACE << "handle not empty";
        }
        LOG_TRACE << "Called handle";
        if (handle(proto)){
            LOG_INFO << "P2P_Protocol connected";
        }

        _protocol = proto;

        //start reading in socket:
        start_read();
    }

    void P2PSocket::write(std::shared_ptr<base_message> msg)
    {
        LOG_DEBUG << "P2PSocket::write, msg->cmd = "<< (int)msg->cmd;
        write_prefix(msg);
    }

    void P2PSocket::write_prefix(std::shared_ptr<base_message> msg)
    {
        LOG_TRACE << "Write prefix method called";
        boost::asio::async_write(_socket, boost::asio::buffer(_net->PREFIX, _net->PREFIX_LENGTH),
                                 [this, msg](boost::system::error_code _ec, std::size_t length)
                                 {
                                    LOG_DEBUG << "Write prefix called";
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

        SendPackedMsg(std::shared_ptr<base_message> msg)
        {
            PackStream value;

            //command [+]
            std::string temp_cmd = c2pool::libnet::messages::string_commands(msg->cmd);
            auto command = new char[12]{'\0'};
            memcpy(command, temp_cmd.c_str(), temp_cmd.size());
            PackStream s_command(command, 12);
            value << s_command;
            delete command;

            //-----
            PackStream payload_stream;
            payload_stream << *msg;

            //len [+]
            IntType(32) unpacked_len(payload_stream.size());
            value << unpacked_len;

            //checksum []
            //sha256(sha256(payload))
//            auto __checksum = coind::data::hash256(payload_stream);
//            IntType(256) checksum_full(__checksum);
//            PackStream _packed_checksum;
//            _packed_checksum << checksum_full;
//            vector <unsigned char> packed_checksum(_packed_checksum.data.begin(), _packed_checksum.data.begin()+4);
//            PackStream checksum(packed_checksum);
//            value << checksum;

            PackStream payload_checksum_stream;
            payload_checksum_stream << *msg;

            std::cout << "payload: ";
            for (auto v : payload_checksum_stream.data){
                std::cout << (unsigned int)v << " ";
            }
            std::cout << "\n";

            auto __checksum = coind::data::hash256(payload_checksum_stream);
            IntType(256) checksum_full(__checksum);
            PackStream _packed_checksum;
            _packed_checksum << checksum_full;
            vector <unsigned char> packed_checksum(_packed_checksum.data.end()-4, _packed_checksum.data.end());



            std::cout << "_packed_checksum: ";
            for (auto v : _packed_checksum.data){
                std::cout << v;
            }
            std::cout << "\n";

            std::cout << "packed_checksum: ";
            for (auto v : packed_checksum){
                std::cout << v;
            }
            std::cout << "\n";

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
        LOG_DEBUG << "Write msg data method called";
        SendPackedMsg msg(_msg);
        boost::asio::async_write(_socket, boost::asio::buffer(msg.data, msg.len),
                                 //TODO?: this -> shared_this()
                                 [this](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG << "Write msg data called";
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
        shared_ptr<ReadPackedMsg> msg = std::make_shared<ReadPackedMsg>(_net->PREFIX_LENGTH);
        LOG_TRACE << "created temp_raw_message";
        //Socket started for reading!
        read_prefix(msg);
    }

    void P2PSocket::read_prefix(shared_ptr<ReadPackedMsg> msg)
    {
        LOG_TRACE << "socket status: " << _socket.is_open();
        boost::asio::async_read(_socket,
                                boost::asio::buffer(msg->prefix, _net->PREFIX_LENGTH),
                                [this, msg](boost::system::error_code ec, std::size_t length)
                                {
                                    LOG_TRACE << "try to read prefix";
                                    //TODO: compare
                                    if (!ec /*&& c2pool::dev::compare_str(tempRawMessage->converter->prefix, _net->PREFIX, tempRawMessage->converter->get_prefix_len())*/)
                                    {
                                        LOG_TRACE << "compare prefix";
                                        //c2pool::python::other::debug_log(tempRawMessage->converter->prefix, _net->PREFIX_LENGTH);
                                        LOG_TRACE << "after debug_log";
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
                                        LOG_TRACE << "try to read command: " << msg->command;
                                        //LOG_INFO << "read_command";
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
                                        // LOG_INFO << "read_length";
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
        msg->payload = new char[msg->unpacked_len+1];
        LOG_DEBUG << "unpacked_len: " << msg->unpacked_len;

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
                                        LOG_ERROR << "read_payload: " << ec << " " << ec.message();
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

//        PackStream stream_command(msg->command, msg->COMMAND_LEN);
        std::string cmd(msg->command);
        PackStream stream_payload(msg->payload, msg->unpacked_len);

        stream_RawMsg << stream_payload;

        shared_ptr<raw_message> RawMessage = _protocol.lock()->make_raw_message(cmd);
        //RawMessage->name_type = reverse_string_commands(msg->command);
        stream_RawMsg >> *RawMessage;

        //Protocol handle message
        _protocol.lock()->handle(RawMessage);
    }
} // namespace c2pool::p2p