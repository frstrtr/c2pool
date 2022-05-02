#include "stratum_protocol.h"

#include <iostream>
#include <string>

std::string StratumProtocol::Send(const std::string &request)
{
    auto _req = request + "\n";
    std::cout << "SEND DATA: " << _req << std::endl;
    boost::asio::async_write(*socket, io::buffer(_req.data(),_req.size()), [&](const boost::system::error_code& ec, std::size_t bytes_transferred){
        if (!ec)
        {
            //buffer.consume(buffer.size());
//                    read();
            std::cout << "Writed answer" << std::endl;
        } else {
            std::cout << "Response error: " << ec.message() << std::endl;
        }
    });
    return std::__cxx11::string();
}

StratumProtocol::StratumProtocol(boost::asio::io_context& context) : client(*this, version::v2), acceptor(context), resolver(context)
{
    ip::tcp::endpoint listen_ep(ip::tcp::v4(), 1131);

    acceptor.open(listen_ep.protocol());
    acceptor.set_option(io::socket_base::reuse_address(true));
    acceptor.bind(listen_ep);
    acceptor.listen();
}

void StratumProtocol::listen()
{
    acceptor.async_accept([this](const boost::system::error_code& ec, ip::tcp::socket _socket){
        if (!ec)
        {
            socket = std::make_shared<ip::tcp::socket>(std::move(_socket));
            std::cout << "Connected!" << std::endl;
            read();
            listen();
        } else
        {
            std::cout << ec.message() << std::endl;
        }

    });
}

void StratumProtocol::read()
{
    boost::asio::async_read_until(*socket, buffer, "}\n", [&](const boost::system::error_code& ec, std::size_t len)
    {
        if (buffer.size() == 0)
            return;
        if (!ec)
        {
            std::string data(boost::asio::buffer_cast<const char *>(buffer.data()), buffer.size());
            std::cout << "Message data: " << data << std::endl;
            json request = json::parse(data);
            request["jsonrpc"] = "2.0";
            auto response = server.HandleRequest(request.dump());
            std::cout << response << std::endl;
            buffer.consume(len);
            read();
            Send(response);
        } else
        {
            std::cout << "StratumProtocol::read() error: " << ec.message() << std::endl;
        }
    });
}
