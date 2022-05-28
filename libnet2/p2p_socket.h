#pragma once

#include <memory>
#include <utility>

#include "p2p_socket_data.h"
#include <libp2p/socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>

#include <boost/asio.hpp>


class P2PSocket : public Socket, public FundamentalSocketObject<std::shared_ptr<boost::asio::ip::tcp::socket>>, public std::enable_shared_from_this<Socket>
{
private:
    std::shared_ptr<c2pool::Network> net;
public:
    P2PSocket(socket_type _fundamental_socket, handler_type message_handler, std::shared_ptr<c2pool::Network> _net) :
            Socket(std::move(message_handler)),
            FundamentalSocketObject(std::move(_fundamental_socket), shared_from_this()),
            net(_net)
    {

    }

    // Write
    void write_prefix(std::shared_ptr<Message> msg);
    void write_message_data(std::shared_ptr<Message> msg);

    void write(std::shared_ptr<Message> msg) override
    {
        write_prefix(msg);
    }

    // Read
    void read_prefix(std::shared_ptr<ReadSocketData> msg);
    void read_command(std::shared_ptr<ReadSocketData> msg);
    void read_length(std::shared_ptr<ReadSocketData> msg);
    void read_checksum(std::shared_ptr<ReadSocketData> msg);
    void read_payload(std::shared_ptr<ReadSocketData> msg);
    void final_read_message(std::shared_ptr<ReadSocketData> msg);

    void read() override
    {
        std::shared_ptr<ReadSocketData> msg = std::make_shared<ReadSocketData>(net->PREFIX_LENGTH);
        read_prefix(msg);
    }

    bool isConnected() override
    {
        return get_fundamental_socket()->is_open();
    }

    void disconnect() override
    {
        get_fundamental_socket()->close();
    }

    std::tuple<std::string, std::string> get_addr() override
    {
        boost::system::error_code ec;
        auto ep = get_fundamental_socket()->remote_endpoint(ec);
        return {ep.address().to_string(), std::to_string(ep.port())};
    }
};