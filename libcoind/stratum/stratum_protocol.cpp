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
    if (is_closed())
        return; 
    boost::asio::async_read_until(*socket, buffer, "\n", [&](const boost::system::error_code& ec, std::size_t len)
    {
        if (!ec && buffer.size())
        {
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
            auto request_data = request.dump();
            LOG_DEBUG_STRATUM << "StratumProtocol get request = " << request_data;
            
            boost::asio::post(
                *context, 
                [this, req = request_data]
                {
                    auto response = server.HandleRequest(req);
                    
                    // Check, if StratumProtocol disconnected in server.HandleRequest
                    if (!is_closed())
                        Send(response);
                }
            );

            buffer.consume(len);
            Read();
        } else
        {
            if (ec == boost::system::errc::operation_canceled /*|| ec == boost::asio::error::eof*/)
                return;

            if (!buffer.size())
                disconnect("StratumProtocol::read() buffer = 0!");

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
    closed = true;

    socket->cancel();
    socket->close();
    socket.reset();
    event_disconnect->happened();
    LOG_INFO << addr.to_string() << " closed!";
}