#pragma once

#include "jsonrpccxx/client.hpp"
#include "jsonrpccxx/server.hpp"

// #include <libs/jsonrpccxx/client.hpp>
// #include <libs/jsonrpccxx/server.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>

#include <libdevcore/types.h>
#include <libp2p/protocol_components.h>

#include <memory>
using namespace jsonrpccxx;

namespace io = boost::asio;
namespace ip = io::ip;

class StratumProtocol : public jsonrpccxx::IClientConnector
{
public:
//    StratumProtocol();
    StratumProtocol(boost::asio::io_context* context, std::shared_ptr<ip::tcp::socket> socket, std::function<void(NetAddress)> _disconnect_in_node_f);
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

    void disconnect(std::string reason);

protected:
    boost::asio::io_context* _context;

    JsonRpc2Server server;
    JsonRpcClient client;

    std::shared_ptr<ip::tcp::socket> _socket;
    const NetAddress addr;
    std::function<void(NetAddress)> disconnect_in_node_f;
    Event<> event_disconnect;
private:
    io::streambuf buffer;
};
