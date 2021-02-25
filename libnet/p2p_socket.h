#pragma once

#include "p2p_protocol.h"

namespace c2pool::libnet
{
    namespace messages
    {
        class base_message;
    }
} // namespace c2pool

#include <memory>
#include <networks/network.h>
#include <boost/asio.hpp>
#include <boost/function.hpp>
namespace ip = boost::asio::ip;

namespace c2pool::libnet::p2p
{
    typedef boost::function<bool(shared_ptr<c2pool::libnet::p2p::Protocol>)> protocol_handle;

    class P2PSocket : public std::enable_shared_from_this<P2PSocket>
    {
    public:
        P2PSocket(std::shared_ptr<ip::tcp::socket> socket);
        
        void init(protocol_handle const &handle);

        bool isConnected() const { return _socket->is_open(); }
        shared_ptr<ip::tcp::socket> get() { return _socket; }
        void disconnect() { _socket->close(); }

        ip::tcp::endpoint endpoint()
        {
            boost::system::error_code ec;
            return _socket->remote_endpoint(ec);
        }

        void write(std::shared_ptr<base_message> msg);

    private:
        void start_read();
        void read_prefix(shared_ptr<raw_message> tempRawMessage);
        void read_command(shared_ptr<raw_message> tempRawMessage);
        void read_length(shared_ptr<raw_message> tempRawMessage);
        void read_checksum(shared_ptr<raw_message> tempRawMessage);
        void read_payload(shared_ptr<raw_message> tempRawMessage);

    private:
        std::shared_ptr<c2pool::Network> _net;
        std::shared_ptr<boost::asio::ip::tcp::socket> _socket;

        std::weak_ptr<c2pool::libnet::p2p::Protocol> _protocol;
    };
} // namespace c2pool::p2p