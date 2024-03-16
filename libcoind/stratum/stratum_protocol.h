#pragma once

#include "jsonrpccxx/client.hpp"
#include "jsonrpccxx/server.hpp"

// #include <libs/jsonrpccxx/client.hpp>
// #include <libs/jsonrpccxx/server.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>

#include <libdevcore/types.h>
#include <libp2p/protocol_components.h>

#include <string>
#include <memory>
using namespace jsonrpccxx;

namespace io = boost::asio;
namespace ip = io::ip;

class StratumProtocol : public jsonrpccxx::IClientConnector
{
protected:
    using disconnect_func_type = std::function<void(const NetAddress&, std::string, int)>;
public:
//    StratumProtocol();
    StratumProtocol(boost::asio::io_context* context_, std::unique_ptr<ip::tcp::socket> socket_, disconnect_func_type disconnect_func_);
    ~StratumProtocol()
    {
        delete event_disconnect;
    }

    void Read();
    std::string Send(const std::string &request) override;

    auto get_addr() const
    {
        return addr;
    }

    void close();

protected:
    boost::asio::io_context* context;

    JsonRpc2Server server;
    JsonRpcClient client;

    std::unique_ptr<ip::tcp::socket> socket;
    const NetAddress addr;
    disconnect_func_type disconnect_func; // StratumNode::disconnect
    Event<> event_disconnect;

    void disconnect(std::string reason, int ban_time = 10)
    {
        disconnect_func(get_addr(), reason, ban_time);
    }
private:
    io::streambuf buffer;
};
