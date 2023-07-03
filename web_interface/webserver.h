#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>

#include "session_interface.h"
#include "webroot.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;

// Handles an HTTP server connection
class session : public session_interface, public std::enable_shared_from_this<session>
{
    std::shared_ptr<WebRoot> web;

    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    ResponseSender lambda_;

public:
    // Take ownership of the stream
    explicit session(
            tcp::socket&& socket, std::shared_ptr<WebRoot> _web)
            : session_interface(std::move(socket)), web(std::move(_web))
    {
    }

    // Start the asynchronous operation
    void run()
    {
        lambda_ = ResponseSender(std::dynamic_pointer_cast<session_interface>(shared_from_this()));
        do_read();
    }

    void
    do_read()
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(stream_, buffer_, req_,
                         beast::bind_front_handler(
                                 &session_interface::on_read,
                                 shared_from_this()));
    }

    void
    on_read(
            beast::error_code ec,
            std::size_t bytes_transferred) override
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return do_close();

        if(ec)
        {
            //TODO: fail(ec, "read");
            return;
        }

        // Send the response
        web->handle_request(std::move(req_), lambda_);
    }

    void
    on_write(
            bool close,
            beast::error_code ec,
            std::size_t bytes_transferred) override
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
        {
            //TODO: fail(ec, "write");
            return;
        }

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }

    void
    do_close()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

class WebServer : public std::enable_shared_from_this<WebServer>
{
    std::shared_ptr<asio::io_context> ioc;
    std::shared_ptr<WebRoot> web;
    tcp::acceptor acceptor;
    std::shared_ptr<session> _session;

    std::atomic<bool> _is_running{false};
public:
    WebServer(const std::shared_ptr<asio::io_context>& _ioc, tcp::endpoint endpoint) : ioc(_ioc), acceptor(net::make_strand(*ioc))
    {
        boost::system::error_code ec;

        acceptor.open(endpoint.protocol(), ec);
        if (ec)
        {
            //TODO: ERROR IN EC
            return;
        }

        acceptor.set_option(asio::socket_base::reuse_address(true), ec);
        if (ec)
        {
            //TODO: ERROR IN EC
            return;
        }

        acceptor.bind(endpoint, ec);
        if (ec)
        {
            //TODO: ERROR IN EC
            return;
        }

        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            //TODO: ERROR IN EC
            return;
        }
    }

    void add_web_root(std::shared_ptr<WebRoot> _web)
    {
        web = std::move(_web);
    }

    // Start accepting incoming connections
    void run()
    {
        if (!web)
            throw WebInitError("empty web in WebServer");

        do_accept();
        _is_running = true;
    }

    bool is_running() const
    {
        return _is_running;
    }


private:
    void do_accept()
    {
        // The new connection gets its own strand
        acceptor.async_accept(
                asio::make_strand(*ioc),
                beast::bind_front_handler(
                        &WebServer::on_accept,
                        shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket)
    {
        if(ec)
        {
            std::cout << "ON_ACCEPT ERROR: " << ec.message() << std::endl;
            //TODO: fail(ec, "accept");
        }
        else
        {
            // Create the session and run it
            _session = std::make_shared<session>(std::move(socket), web);
            _session->run();
        }

        // Accept another connection
        do_accept();
    }
};