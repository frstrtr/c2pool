#pragma once
//#include <string_view>
//#include <string>

#include <list>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <utility>

#include "session_interface.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>

// Return a reasonable mime type based on the extension of a file.
beast::string_view
mime_type(beast::string_view path);

std::list<std::string> split(const std::string& str, char delimiter);

struct UrlData
{
    std::string full_path;
    std::list<std::string> path;
    std::map<std::string, std::string> query;

    typedef std::list<std::string>::iterator path_it;
};

UrlData parse_url(const std::string& url);


struct RequestData
{
    // request data:
    http::verb method;
    UrlData url;
    unsigned version;
    std::function<bool()> keep_alive;

//    RequestData(http::verb _method, unsigned _version, std::function<bool()> _alive) : method(_method), version(_version), keep_alive(std::move(_alive)) {}
};

struct ResponseSender
{

    std::shared_ptr<session_interface> self_;

    ResponseSender() = default;
    explicit ResponseSender(std::shared_ptr<session_interface> self) : self_(std::move(self)) {}

    template<bool isRequest, class Body, class Fields>
    void
    operator()(http::message<isRequest, Body, Fields>&& msg) const
    {
        // The lifetime of the message has to extend
        // for the duration of the async operation so
        // we use a shared_ptr to manage it.
        auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

        // Store a type-erased version of the shared
        // pointer in the class to keep it alive.
        self_->res_ = sp;

        // Write the response
        http::async_write(
                self_->stream_,
                *sp,
                beast::bind_front_handler(
                        &session_interface::on_write,
                        self_,
                        sp->need_eof()));
    }
};