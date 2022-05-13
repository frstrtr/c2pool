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
    StratumProtocol(std::shared_ptr<boost::asio::io_context> context);

    void listen();
    void read();

    std::string Send(const std::string &request) override;

    void disconnect();

protected:
    std::shared_ptr<boost::asio::io_context> _context;

    JsonRpc2Server server;
    JsonRpcClient client;

    ip::tcp::acceptor acceptor;
    ip::tcp::resolver resolver;

    std::shared_ptr<ip::tcp::socket> socket;

private:
    io::streambuf buffer;
//    io::steady_timer listen_timer

};
