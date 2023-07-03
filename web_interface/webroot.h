#pragma once

#include <iostream>

#include <map>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>

#include "webnode.h"

// Example:
//      auto& net_root = web_root->new_net("dgb");
//      new_root->set("shares_count", json);

class NetDataField
{
    std::shared_mutex mutex_;

    std::unordered_map<std::string, std::string> data; // key -- variable name; value -- json value
public:

    std::string get(const std::string& var_name)
    {
        std::shared_lock lock(mutex_);
        //TODO: throw WebNotFound?
        return data.count(var_name) ? data.at(var_name) : "";
    }

    void set(const std::string &var_name, const std::string &value)
    {
        std::unique_lock lock(mutex_);
        data[var_name] = value;
    }
};

class WebRoot
{
protected:
    std::shared_ptr<WebInterface> web;

    std::unordered_map<std::string, std::unique_ptr<NetDataField>> datas; // key -- net_name;
protected:
    template<class Body, class Allocator>
    auto bad_request(http::request<Body, http::basic_fields<Allocator>>& req, std::string_view why)
    {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    }

    template<class Body, class Allocator>
    auto not_found(http::request<Body, http::basic_fields<Allocator>>& req, std::string_view target)
    {
        http::response<http::string_body> res{http::status::not_found, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "The resource '" + std::string(target) + "' was not found.";
        res.prepare_payload();
        return res;
    }

    template<class Body, class Allocator>
    auto server_error(http::request<Body, http::basic_fields<Allocator>>& req, std::string_view what)
    {
        http::response<http::string_body> res{http::status::internal_server_error, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    }

    // Append an HTTP rel-path to a local filesystem path.
// The returned path is normalized for the platform.
    std::string path_cat(
            beast::string_view base,
            beast::string_view path)
    {
        if (base.empty())
            return std::string(path);
        std::string result(base);
#ifdef BOOST_MSVC
        char constexpr path_separator = '\\';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for(auto& c : result)
        if(c == '/')
            c = path_separator;
#else
        char constexpr path_separator = '/';
        if (result.back() == path_separator)
            result.resize(result.size() - 1);
        result.append(path.data(), path.size());
#endif
        return result;
    }
public:
    explicit WebRoot(typename WebInterface::func_type&& func)
    {
        web = std::make_shared<WebInterface>(std::move(func));
    }

    std::shared_ptr<WebInterface> get_interface(){
        return web;
    }

    NetDataField& net(const std::string &net_name)
    {
        return *datas[net_name];
    }

    NetDataField& new_net(const std::string &net_name)
    {
        datas[net_name] = std::make_unique<NetDataField>();
        return *datas[net_name];
    }

    bool exist_net(const std::string &net_name)
    {
        return datas.count(net_name);
    }

    template<
            class Body, class Allocator,
            class Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req,
                        Send&& send)
    {
        // Make sure we can handle the method
        if( req.method() != http::verb::get &&
            req.method() != http::verb::head)
            return send(bad_request(req, "Unknown HTTP-method"));

        // Request path must be absolute and not contain "..".
        if( req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != beast::string_view::npos)
            return send(bad_request(req, "Illegal request-target"));

        //path
        //TODO: remove "." for custom path
        std::string path = path_cat(".", req.target());
        // send index.html if target end = ".../.../"
//        if(req.target().back() == '/')
//            path.append("index.html");

        RequestData rq{req.method(), parse_url(path), req.version(), [&](){return req.keep_alive();}};

        try
        {
            web->handle(rq, rq.url.path.begin(), send);
        }
        catch (const WebNotFound& e)
        {
            std::cout << "WebNotFound: " << e.what() << std::endl;
            send(not_found(req, e.what()));
        }
        catch (const WebServerError& e)
        {
            std::cout << "WebServerError: " << e.what() << std::endl;
            send(server_error(req, e.what()));
        }
        catch (const WebBadRequest& e)
        {
            std::cout << "WebBadRequest: " << e.what() << std::endl;
            send(bad_request(req, e.what()));
        }
    }
};
