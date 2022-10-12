#pragma once

#include <libs/jsonrpccxx/client.hpp>
#include <libs/jsonrpccxx/server.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>

#include <memory>
using namespace jsonrpccxx;

namespace io = boost::asio;
namespace ip = io::ip;

class StratumProtocol : public jsonrpccxx::IClientConnector
{
public:
    StratumProtocol();
    StratumProtocol(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_event);

    void read();

    std::string Send(const std::string &request) override;

    auto get_addr() const
    {
        return std::make_tuple(_socket->remote_endpoint().address().to_string(), _socket->remote_endpoint().port());
    }

    void disconnect();

protected:
    std::shared_ptr<boost::asio::io_context> _context;

    JsonRpc2Server server;
    JsonRpcClient client;

    std::shared_ptr<ip::tcp::socket> _socket;
    const std::tuple<std::string, unsigned short> addr;
    std::function<void(std::tuple<std::string, unsigned short>)> disconnect_event;
private:
    io::streambuf buffer;
//    io::steady_timer listen_timer

};
