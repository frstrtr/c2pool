#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>

#include <memory>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;

class session_interface //: public std::enable_shared_from_this<session_interface>
{
public:
    std::shared_ptr<void> res_;
    beast::tcp_stream stream_;

public:
    explicit session_interface(tcp::socket&& socket) : stream_(std::move(socket)) {}

    virtual void on_read(
            beast::error_code ec,
            std::size_t bytes_transferred) = 0;

    virtual void on_write(
            bool close,
            beast::error_code ec,
            std::size_t bytes_transferred) = 0;
};