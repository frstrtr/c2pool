#include "stratum_protocol.h"

#include <iostream>
#include <string>
#include <libdevcore/logger.h>

StratumProtocol::StratumProtocol(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_in_node_f) : ProtocolEvents(), _context(std::move(context)), _socket(std::move(socket)), client(*this, version::v2), disconnect_in_node_f(std::move(_disconnect_in_node_f)),
                                                                                                                                                                                                              addr(std::make_tuple(_socket->remote_endpoint().address().to_string(), _socket->remote_endpoint().port()))
{
    Read();
}

void StratumProtocol::Read()
{
    boost::asio::async_read_until(*_socket, buffer, "\n", [&](const boost::system::error_code& ec, std::size_t len)
    {
        if (!ec)
        {
            if (buffer.size() == 0)
                return;

            std::string data(boost::asio::buffer_cast<const char *>(buffer.data()), len);
            std::cout << "Message data: <" << data << ">." << std::endl;

            json request;
            try
            {
                request = json::parse(data);
            } catch (const std::exception &exception)
            {
                LOG_WARNING << "StratumProtocol::read error while parsing: " << exception.what();
            }
            request["jsonrpc"] = "2.0";
            std::cout << "request: " << request.dump() << std::endl;
            auto response = server.HandleRequest(request.dump());
            std::cout << "response: " << response << std::endl;
            buffer.consume(len);
            Read();
            Send(response);
        } else
        {
            disconnect("StratumProtocol::read() error = " + ec.message());
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
            disconnect("Response error = " + ec.message());
        }
    });
    return {};
}

void StratumProtocol::disconnect(std::string reason)
{
    auto [ip, port] = get_addr();
    LOG_WARNING << "StratumProtocol(" << ip << ":" << port << ") has been disconnected for a reason: " << reason;
    event_disconnect.happened();
    _socket->close();
    disconnect_in_node_f(get_addr());
}