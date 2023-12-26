#pragma once

#include <libs/jsonrpccxx/client.hpp>
#include <libs/jsonrpccxx/server.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>

#include <libp2p/protocol_events.h>

#include <memory>
using namespace jsonrpccxx;

namespace io = boost::asio;
namespace ip = io::ip;

class StratumProtocol : public jsonrpccxx::IClientConnector, protected virtual ProtocolEvents
{
public:
//    StratumProtocol();
    StratumProtocol(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_in_node_f);
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
    std::shared_ptr<boost::asio::io_context> _context;

    JsonRpc2Server server;
    JsonRpcClient client;

    std::shared_ptr<ip::tcp::socket> _socket;
    const std::tuple<std::string, unsigned short> addr;
    std::function<void(std::tuple<std::string, unsigned short>)> disconnect_in_node_f;
    Event<> event_disconnect;
private:
    io::streambuf buffer;
};
