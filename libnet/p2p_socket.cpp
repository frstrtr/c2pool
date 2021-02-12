#include "p2p_socket.h"
#include <util/messages.h>

#include <memory>

#include <boost/asio.hpp>
namespace ip = boost::asio::ip;

namespace c2pool::p2p
{
    P2PSocket::P2PSocket(ip::tcp::socket socket) : _socket(std::move(socket))
    {
        //TODO: check p2pool/c2pool node
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

    void read_prefix();
    void read_command();
    void read_length();
    void read_checksum();
    void read_payload();
} // namespace c2pool::p2p