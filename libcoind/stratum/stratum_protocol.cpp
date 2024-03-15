#include "stratum_protocol.h"

#include <iostream>
#include <string>
#include <libdevcore/logger.h>

StratumProtocol::StratumProtocol(boost::asio::io_context* context_, std::unique_ptr<ip::tcp::socket> socket_, disconnect_func_type disconnect_func_) 
    : context(context_), socket(std::move(socket_)), 
        client(*this, version::v2), disconnect_func(std::move(disconnect_func_)), 
        addr(socket->remote_endpoint())
{
    event_disconnect = make_event();
    Read();
}

void StratumProtocol::Read()
{
    boost::asio::async_read_until(*socket, buffer, "\n", [&](const boost::system::error_code& ec, std::size_t len)
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
            if (ec == boost::system::errc::operation_canceled /*|| ec == boost::asio::error::eof*/)
                return;

            disconnect("StratumProtocol::read() error = " + ec.message());
        }
    });
}

std::string StratumProtocol::Send(const std::string &request)
{
    auto _req = request + "\n";
    LOG_DEBUG_STRATUM << "StratumProtocol send message: " << request;
    boost::asio::async_write(*socket, io::buffer(_req.data(),_req.size()), 
        [&](const boost::system::error_code& ec, std::size_t bytes_transferred)
        {
            if (ec)
            {
                if (ec == boost::system::errc::operation_canceled /*|| ec == boost::asio::error::eof*/)
                    return;
                    
                disconnect("Response error = " + ec.message());
            }
        }
    );
    return {};
}

void StratumProtocol::close()
{
    socket->cancel();
    socket->close();
    event_disconnect->happened();
}