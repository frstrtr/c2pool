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
    Read(0);
}

void StratumProtocol::Read(int i)
{
    if (!socket || !socket->is_open())
    {
        return; // exit
    }

    boost::asio::async_read_until(*socket, buffer, "\n", [&, i = i](const boost::system::error_code& ec, std::size_t len)
    {
        LOG_INFO << i << ":"  << "TEST SOCKET " << (bool)socket;
        if (!socket || !socket->is_open())
        {
            return; // exit
        }
        LOG_INFO << i << ":" << 1;

        if (!ec && buffer.size())
        {
            LOG_INFO << i << ":"  << 2;
            std::string data(boost::asio::buffer_cast<const char *>(buffer.data()), len);
            LOG_INFO << i << ":"  << 3;
            json request;
            try
            {
                request = json::parse(data);
                LOG_INFO << i << ":"  << 4;
            } catch (...)
            {
                LOG_WARNING << "StratumProtocol::read error while parsing data :" << data;
            }
            request["jsonrpc"] = "2.0";
            LOG_DEBUG_STRATUM << "StratumProtocol get request = " << request.dump();
            LOG_INFO << i << ":"  << 5;
            auto response = server.HandleRequest(request.dump());
            LOG_INFO << i << ":"  << 6;
            buffer.consume(len);
            LOG_INFO << i << ":"  << 7;
            Read(i+1);
            LOG_INFO << i << ":"  << 8;
            Send(response);
            LOG_INFO << i << ":"  << 9;
        } else
        {
            LOG_INFO << i << ":"  << 10;
            if (ec == boost::system::errc::operation_canceled /*|| ec == boost::asio::error::eof*/)
                return;

            if (!buffer.size())
                disconnect("StratumProtocol::read() buffer = 0!");

            disconnect("StratumProtocol::read() error = " + ec.message());
        }
        LOG_INFO << i << ":"  << 11;
    });
    LOG_INFO << i << ":"  << 12;
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
    socket.reset();
    event_disconnect->happened();
    LOG_INFO << addr.to_string() << " closed! " << (bool)socket;
}