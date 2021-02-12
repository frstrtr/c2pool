#pragma once

namespace c2pool
{
    namespace messages
    {
        class message;
    }
} // namespace c2pool

#include <memory>

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
        void disconnect() { _socket.close(); }

        ip::tcp::endpoint endpoint()
        {
            boost::system::error_code ec;
            return _socket.remote_endpoint(ec);
        }

        void write(std::shared_ptr<c2pool::messages::message> msg);

        void read_prefix();
        void read_command();
        void read_length();
        void read_checksum();
        void read_payload();

        //TODO: очередь из сообщений???

    private:
        boost::asio::ip::tcp::socket _socket;
    };
} // namespace c2pool::p2p