#include "stratum_protocol.h"

#include <iostream>
#include <string>


StratumProtocol::StratumProtocol(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_event) : _context(std::move(context)), _socket(std::move(socket)), client(*this, version::v2), disconnect_event(std::move(_disconnect_event)),
    addr(std::make_tuple(_socket->remote_endpoint().address().to_string(), _socket->remote_endpoint().port()))
{
    read();
}

void StratumProtocol::read()
{
    boost::asio::async_read_until(*_socket, buffer, "\n", [&](const boost::system::error_code& ec, std::size_t len)
    {
        if (buffer.size() == 0)
            return;
        if (!ec)
        {
            std::string data(boost::asio::buffer_cast<const char *>(buffer.data()), len);
            std::cout << "Message data: " << data << std::endl;
            json request = json::parse(data);
            request["jsonrpc"] = "2.0";
            std::cout << "request: " << request.dump() << std::endl;
            auto response = server.HandleRequest(request.dump());
            std::cout << "response: " << response << std::endl;
            buffer.consume(len);
            read();
            Send(response);
        } else
        {
            std::cout << "StratumProtocol::read() error: " << ec.message() << std::endl;
        }
    });
}

std::string StratumProtocol::Send(const std::string &request)
{
    auto _req = request + "\n";
    std::cout << "SEND DATA: " << _req;
    boost::asio::async_write(*_socket, io::buffer(_req.data(),_req.size()), [&](const boost::system::error_code& ec, std::size_t bytes_transferred){
        if (!ec)
        {
            //buffer.consume(buffer.size());
//                    read();
            std::cout << "Writed answer" << std::endl;
        } else {
            std::cout << "Response error: " << ec.message() << std::endl;
        }
    });
    return {};
}

void StratumProtocol::disconnect()
{
    _socket->close();
    disconnect_event(get_addr());
}