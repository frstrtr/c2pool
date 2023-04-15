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

            json request;
            try
            {
                request = json::parse(data);
            } catch (...)
            {
                LOG_WARNING << "StratumProtocol::read error while parsing data :" << data;
            }
            request["jsonrpc"] = "2.0";
            LOG_DEBUG_STRATUM << "StratumProtocol get request = " << request.dump();
            auto response = server.HandleRequest(request.dump());

            buffer.consume(len);
            Read();
            Send(response);
        } else
        {
            if (ec == boost::system::errc::operation_canceled)
                return;

            disconnect("StratumProtocol::read() error = " + ec.message());
        }
    });
}

std::string StratumProtocol::Send(const std::string &request)
{
    auto _req = request + "\n";
    LOG_DEBUG_STRATUM << "StratumProtocol send message: " << request;
    boost::asio::async_write(*_socket, io::buffer(_req.data(),_req.size()), [&](const boost::system::error_code& ec, std::size_t bytes_transferred){
        if (ec)
        {
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