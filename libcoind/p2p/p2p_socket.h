#pragma once

#include "messages.h"
#include <networks/network.h>
using namespace coind::p2p::messages;

namespace coind::p2p
{
    class CoindProtocol;
}

#include <memory>
#include <boost/asio.hpp>
#include <boost/function.hpp>
namespace ip = boost::asio::ip;

namespace coind::p2p
{
    struct ReadPackedMsg
    {
        const int COMMAND_LEN = 12;
        const int LEN_LEN = 4;
        const int CHECKSUM_LEN = 4;

        char *prefix;
        char *command;
        char *len;
        char *checksum;
        char *payload;

        int32_t unpacked_len;

        ReadPackedMsg(int32_t pref_len)
        {
            prefix = new char[pref_len];
            command = new char[COMMAND_LEN];
            len = new char[LEN_LEN];
            checksum = new char[CHECKSUM_LEN];
        }

        ~ReadPackedMsg()
        {
            delete prefix;
            delete command;
            delete len;
            delete checksum;
            delete payload;
        }
    };
}

namespace coind::p2p
{
    class P2PSocket : public std::enable_shared_from_this<P2PSocket>
    {
    public:
        //for receive
        P2PSocket(ip::tcp::socket socket, std::shared_ptr<coind::ParentNetwork> __parent_net);

        //for connect
        void init(const boost::asio::ip::tcp::resolver::results_type endpoints, shared_ptr<coind::p2p::CoindProtocol> proto);
        void connectionMade(boost::asio::ip::tcp::endpoint ep);

        bool isConnected() const { return _socket.is_open(); }
        ip::tcp::socket &get() { return _socket; }
        void disconnect() { _socket.close(); }

        ip::tcp::endpoint endpoint()
        {
            boost::system::error_code ec;
            return _socket.remote_endpoint(ec);
        }

        void write(std::shared_ptr<base_message> msg);

    private:
        void start_read();
        void read_prefix(std::shared_ptr<ReadPackedMsg> msg);
        void read_command(std::shared_ptr<ReadPackedMsg> msg);
        void read_length(std::shared_ptr<ReadPackedMsg> msg);
        void read_checksum(std::shared_ptr<ReadPackedMsg> msg);
        void read_payload(std::shared_ptr<ReadPackedMsg> msg);
        void final_read_message(std::shared_ptr<ReadPackedMsg> msg);

        void write_prefix(std::shared_ptr<base_message> msg);
        void write_message_data(std::shared_ptr<base_message> msg);

    private:
        ip::tcp::socket _socket;

        std::weak_ptr<coind::p2p::CoindProtocol> _protocol;
        std::shared_ptr<coind::ParentNetwork> _parent_net;
    };
} // namespace c2pool::p2p