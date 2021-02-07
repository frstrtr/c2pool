#include "p2p_socket.h"
#include <boost/asio.hpp>
namespace ip = boost::asio::ip;

namespace c2pool::p2p{
    P2PSocket::P2PSocket(ip::tcp::socket socket) : _socket(std::move(socket)){
        //TODO: check p2pool/c2pool node
    }
}