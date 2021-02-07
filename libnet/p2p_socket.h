#pragma once
#include <boost/asio.hpp>
namespace ip = boost::asio::ip;

namespace c2pool::p2p
{
    class P2PSocket
    {
    public:
        P2PSocket(ip::tcp::socket socket);

        bool isConnected() const { return _socket.is_open(); }
        ip::tcp::socket &get() { return _socket; }
        
        ip::tcp::endpoint endpoint()
        {
            boost::system::error_code ec;
            return _socket.remote_endpoint(ec);
        }


    private:
        boost::asio::ip::tcp::socket _socket;
    };
} // namespace p2pool::p2p