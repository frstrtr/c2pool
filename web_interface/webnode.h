#pragma once

#include <list>
#include <string>
#include <string_view>
#include <map>

#include "response_sender.h"
#include "webexcept.h"
#include "netdatafield.h"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/format.hpp>
//#include <filesystem>
#include <iostream>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

bool isDirectory(const std::string& path);

class WebNode : public std::enable_shared_from_this<WebNode>
{
public:
    virtual void handle(const RequestData& rq, std::list<std::string>::iterator path_pos, ResponseSender &sender) = 0;
};

// For web tree logic
class WebInterface : public WebNode
{
public:
    typedef std::function<void(const std::map<std::string, std::string>&)> func_type;
protected:
    /// query func
    func_type func;

    std::map<std::string, std::shared_ptr<WebNode>> childs;
public:

    explicit WebInterface(func_type &&_func) : func(std::move(_func)) {}

    template <typename NodeType, typename... Args>
    std::shared_ptr<NodeType> put_child(const std::string& key, Args... args)
    {
        auto node = std::make_shared<NodeType>(args...);
        childs[key] = node;
        return node;
    }

    std::shared_ptr<WebNode> get_child(const std::string& key)
    {
        return childs.count(key) ? childs[key] : nullptr;
    }

    void handle(const RequestData& rq, std::list<std::string>::iterator path_pos, ResponseSender &sender) override
    {
        if (path_pos != rq.url.path.end() && childs.count(*path_pos))
        {
            return childs[*path_pos]->handle(rq, ++path_pos, sender);
        }

        std::string file_path = rq.url.full_path;

        if (isDirectory(file_path))
        {
            file_path += "/index.html";
            if (func && !rq.url.query.empty())
                func(rq.url.query);
        }

        beast::error_code ec;
        http::file_body::value_type body;
        body.open(file_path.c_str(), beast::file_mode::scan, ec);

        // Handle the case where the file doesn't exist
        if (ec == beast::errc::no_such_file_or_directory)
            throw WebNotFound(rq.url.full_path);
//                return send(not_found(req.target()));

        // Handle an unknown error
        if (ec)
            throw WebServerError(ec.message());
//                return send(server_error(ec.message()));

        // Cache the size since we need it after the move
        auto const size = body.size();

        // Respond to HEAD request
        if (rq.method == http::verb::head)
        {
            http::response<http::empty_body> res{http::status::ok, rq.version};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, mime_type(file_path));
            res.content_length(size);
            res.keep_alive(rq.keep_alive());
            return sender(std::move(res));
        }

        // Respond to GET request
        http::response<http::file_body> res{
                std::piecewise_construct,
                std::make_tuple(std::move(body)),
                std::make_tuple(http::status::ok, rq.version)};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, mime_type(file_path));
        res.content_length(size);
        res.keep_alive(rq.keep_alive());
        return sender(std::move(res));


        throw std::invalid_argument("WebInterface can't send directory");
    }
};

// For directories with files
class WebDirectory : public WebNode
{
    std::map<std::string_view, std::shared_ptr<WebDirectory>> sub_dirs;
public:

    // todo: recursive open folder
    explicit WebDirectory(bool recursive = false) {}

    /// Put sub_dir for this directory
    std::shared_ptr<WebDirectory> put_sub(const std::string_view&& dir_name, bool recursive = false)
    {
        auto sub_dir = std::make_shared<WebDirectory>(recursive);
        sub_dirs[dir_name] = sub_dir;
        return sub_dir;
    }

    void handle(const RequestData& rq, UrlData::path_it path_pos, ResponseSender &sender) override
    {
        if (path_pos != (--rq.url.path.end()))
        {
//            std::string sub_dir(root_path.front());
//            root_path.pop_front();

            if (sub_dirs.count(*path_pos))
                return sub_dirs[*path_pos]->handle(rq, ++path_pos, sender);
            else
                throw WebNotFound((boost::format("Not found sub_dir: %1% ") % *path_pos).str());
        }

        if (path_pos == (--rq.url.path.end()))
        {
            // Attempt to open the file
            beast::error_code ec;
            http::file_body::value_type body;
            body.open(rq.url.full_path.c_str(), beast::file_mode::scan, ec);

            // Handle the case where the file doesn't exist
            if(ec == beast::errc::no_such_file_or_directory)
                throw WebNotFound(rq.url.full_path);
//                return send(not_found(req.target()));

            // Handle an unknown error
            if(ec)
                throw WebServerError(ec.message());
//                return send(server_error(ec.message()));

            // Cache the size since we need it after the move
            auto const size = body.size();

            // Respond to HEAD request
            if(rq.method == http::verb::head)
            {
                http::response<http::empty_body> res{http::status::ok, rq.version};
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, mime_type(rq.url.full_path));
                res.content_length(size);
                res.keep_alive(rq.keep_alive());
                return sender(std::move(res));
            }

            // Respond to GET request
            http::response<http::file_body> res{
                    std::piecewise_construct,
                    std::make_tuple(std::move(body)),
                    std::make_tuple(http::status::ok, rq.version)};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, mime_type(rq.url.full_path));
            res.content_length(size);
            res.keep_alive(rq.keep_alive());
            return sender(std::move(res));
        }

        throw std::invalid_argument("WebDirectory can't send directory");
    }
};

// For dynamic json generate
class WebJson : public WebNode
{
public:
    typedef std::function<std::string(const std::map<std::string, std::string>&)> func_type;
protected:
    func_type func;

public:

    explicit WebJson(func_type &&_func) : func(std::move(_func)) {}

    void handle(const RequestData& rq, UrlData::path_it path_pos, ResponseSender &sender) override
    {
        http::response<http::dynamic_body> response_;

//        http::response<http::file_body> res{
//                std::piecewise_construct,
//                std::make_tuple(std::move(body)),
//                std::make_tuple(http::status::ok, req.version())};
//        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//        res.set(http::field::content_type, "application/json");
//        res.content_length(size);
//        res.keep_alive(req.keep_alive());


        response_.set(http::field::content_type, "application/json");
        beast::ostream(response_.body()) << func(rq.url.query);
        return sender(std::move(response_));
    }
};

// For dynamic net-json generate
class WebNetJson : public WebNode
{
public:
    typedef std::shared_ptr<NetDataField> net_field;
    typedef std::function<net_field(const std::string &net_name)> get_net_func_type;
    typedef std::function<std::string(net_field, const std::map<std::string, std::string>&)> func_type;
protected:
    get_net_func_type get_net_func;
    func_type func;

public:

    explicit WebNetJson(get_net_func_type &_get_net_func, func_type &&_func) : get_net_func(std::move(_get_net_func)), func(std::move(_func)) {}

    void handle(const RequestData& rq, UrlData::path_it path_pos, ResponseSender &sender) override
    {
        http::response<http::dynamic_body> response_;

//        http::response<http::file_body> res{
//                std::piecewise_construct,
//                std::make_tuple(std::move(body)),
//                std::make_tuple(http::status::ok, req.version())};
//        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//        res.set(http::field::content_type, "application/json");
//        res.content_length(size);
//        res.keep_alive(req.keep_alive());


        response_.set(http::field::content_type, "application/json");
        std::string net_name;
        if (rq.url.query.count("net"))
            net_name = rq.url.query.at("net");
        else
            throw WebBadRequest("In query not exist net field!");

        auto net = get_net_func(net_name);

        beast::ostream(response_.body()) << func(std::move(net), rq.url.query);
        return sender(std::move(response_));
    }
};