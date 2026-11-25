// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Helpers for the HTTP-on-the-stratum-port tests (stratum_port_http_*_test.cpp):
// a blocking raw TCP client with timeouts, an HTTP response parser over the
// raw bytes, free-port and local-address discovery, and a WebServer whose own
// stratum acceptor (the LTC lane's wiring) runs on a driven io_context.
#pragma once

#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include <core/web_server.hpp>

namespace stratum_http_test {

namespace net = boost::asio;
using tcp = net::ip::tcp;
using namespace std::chrono_literals;

/// A port nobody listens on right now at `addr` (bind :0, read, release).
inline uint16_t free_port(const std::string& addr = "127.0.0.1")
{
    net::io_context io;
    tcp::acceptor a(io);
    tcp::endpoint ep(net::ip::make_address(addr), 0);
    a.open(ep.protocol());
    a.bind(ep);
    const uint16_t p = a.local_endpoint().port();
    a.close();
    return p;
}

/// This host's address on its default route (no packet is sent: a UDP
/// connect only picks the route). nullopt when there is none, or it is
/// loopback.
inline std::optional<std::string> non_loopback_local_ipv4()
{
    net::io_context io;
    net::ip::udp::socket s(io);
    boost::system::error_code ec;
    s.open(net::ip::udp::v4(), ec);
    if (ec) return std::nullopt;
    s.connect(net::ip::udp::endpoint(net::ip::make_address("192.0.2.1"), 9), ec);
    if (ec) return std::nullopt;
    const auto a = s.local_endpoint(ec).address();
    if (ec || a.is_loopback() || a.is_unspecified()) return std::nullopt;
    return a.to_string();
}

/// A blocking TCP client with timeouts.
class RawClient {
public:
    RawClient() : sock_(io_) {}

    bool connect(const std::string& addr, uint16_t port, const std::string& from = {})
    {
        boost::system::error_code ec;
        const tcp::endpoint to(net::ip::make_address(addr), port);
        sock_.open(to.protocol(), ec);
        if (!ec && !from.empty())
            sock_.bind(tcp::endpoint(net::ip::make_address(from), 0), ec);
        if (!ec)
            sock_.connect(to, ec);
        return !ec;
    }

    void send(const std::string& bytes)
    {
        boost::system::error_code ec;
        net::write(sock_, net::buffer(bytes), ec);
    }

    /// Read what arrives until the peer closes or `timeout` passes. closed()
    /// tells which.
    std::string read_all(std::chrono::milliseconds timeout = 5000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!closed_ && std::chrono::steady_clock::now() < deadline) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            read_some(left);
        }
        return std::exchange(received_, std::string{});
    }

    /// Read until `n` bytes or a '\n'-terminated line are buffered, the peer
    /// closes, or the timeout passes. Returns the first line (without '\n').
    std::optional<std::string> read_line(std::chrono::milliseconds timeout = 3000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (received_.find('\n') == std::string::npos && !closed_
               && std::chrono::steady_clock::now() < deadline) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            read_some(left);
        }
        const auto nl = received_.find('\n');
        if (nl == std::string::npos) return std::nullopt;
        std::string line = received_.substr(0, nl);
        received_.erase(0, nl + 1);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        return line;
    }

    /// Nothing arrives and the connection stays open for `quiet`.
    bool silent_for(std::chrono::milliseconds quiet)
    {
        read_some(quiet);
        return received_.empty() && !closed_;
    }

    bool closed() const { return closed_; }
    tcp::socket& socket() { return sock_; }
    void close()
    {
        boost::system::error_code ec;
        sock_.shutdown(tcp::socket::shutdown_both, ec);
        sock_.close(ec);
    }

private:
    void read_some(std::chrono::milliseconds timeout)
    {
        bool done = false;
        sock_.async_read_some(net::buffer(buf_),
            [&](boost::system::error_code ec, std::size_t n) {
                done = true;
                if (n) received_.append(buf_.data(), n);
                if (ec && ec != net::error::operation_aborted) closed_ = true;
            });
        io_.restart();
        io_.run_for(timeout);
        if (!done) {
            boost::system::error_code ec;
            sock_.cancel(ec);
            io_.restart();
            io_.run();
        }
    }

    net::io_context io_;
    tcp::socket sock_;
    std::array<char, 4096> buf_{};
    std::string received_;
    bool closed_ = false;
};

/// An HTTP/1.x response split out of raw bytes (enough for these tests: one
/// response, Content-Length framing).
struct Response {
    bool ok = false;           // a status line was parsed
    unsigned status = 0;
    std::map<std::string, std::string> headers;   // lower-cased names
    std::string body;          // every byte after the header block
    std::string raw;

    std::string header(const std::string& lower_name) const
    {
        auto it = headers.find(lower_name);
        return it == headers.end() ? std::string{} : it->second;
    }
};

inline Response parse_response(const std::string& raw)
{
    Response r;
    r.raw = raw;
    const auto end = raw.find("\r\n\r\n");
    if (raw.rfind("HTTP/1.", 0) != 0 || end == std::string::npos)
        return r;
    const std::string head = raw.substr(0, end);
    r.body = raw.substr(end + 4);
    std::size_t pos = head.find("\r\n");
    const std::string status_line = head.substr(0, pos);
    const auto sp = status_line.find(' ');
    if (sp == std::string::npos) return r;
    r.status = static_cast<unsigned>(std::stoul(status_line.substr(sp + 1, 3)));
    while (pos != std::string::npos && pos < head.size()) {
        const auto next = head.find("\r\n", pos + 2);
        const std::string line = head.substr(pos + 2, next == std::string::npos ? std::string::npos
                                                                               : next - pos - 2);
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            std::string value = line.substr(colon + 1);
            while (!value.empty() && value.front() == ' ') value.erase(0, 1);
            r.headers[name] = value;
        }
        pos = next;
    }
    r.ok = true;
    return r;
}

/// One request (raw bytes) on a fresh connection; the response read until
/// the server closes.
inline Response exchange(const std::string& addr, uint16_t port, const std::string& request,
                         const std::string& from = {}, std::chrono::milliseconds timeout = 5000ms)
{
    RawClient c;
    if (!c.connect(addr, port, from))
        return {};
    c.send(request);
    return parse_response(c.read_all(timeout));
}

inline std::string request(const std::string& method, const std::string& target,
                           const std::string& extra_headers = {}, const std::string& body = {})
{
    std::string r = method + " " + target + " HTTP/1.1\r\nHost: test\r\n" + extra_headers;
    if (!body.empty() || method == "POST")
        r += "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
    return r + "\r\n" + body;
}

/// A WebServer with its own stratum acceptor (the LTC lane's wiring, both on
/// the web server's bind address); the stratum io_context runs on a thread.
/// --stratum-http is `mode` (auto unless set; nullopt: the server's default).
class WebNode {
public:
    net::io_context ioc;
    std::unique_ptr<core::WebServer> web;
    uint16_t web_port = 0;
    uint16_t stratum_port = 0;
    std::string bind;
    std::optional<core::StratumHttpMode> mode = core::StratumHttpMode::Auto;

    /// configure: called after construction, before start() (stratum config,
    /// --stratum-http mode, ...).
    template <typename Configure>
    bool start(const std::string& bind_addr, Configure&& configure)
    {
        bind = bind_addr;
        web = std::make_unique<core::WebServer>(ioc, bind_addr, 0, false);
        for (int attempt = 0; attempt < 20; ++attempt) {
            stratum_port = free_port(bind_addr);
            web->set_stratum_port(stratum_port);
            if (mode)
                web->set_stratum_http_mode(*mode);
            configure(*web);
            if (web->start() && web->is_stratum_running())
                break;
            web.reset();
            web = std::make_unique<core::WebServer>(ioc, bind_addr, 0, false);
        }
        if (!web || !web->is_stratum_running())
            return false;
        web_port = web->bound_port();
        guard_.emplace(net::make_work_guard(ioc));
        th_ = std::thread([this] { ioc.run(); });
        return true;
    }

    bool start(const std::string& bind_addr)
    {
        return start(bind_addr, [](core::WebServer&) {});
    }

    ~WebNode()
    {
        guard_.reset();
        ioc.stop();
        if (th_.joinable()) th_.join();
        web.reset();
    }

private:
    std::optional<net::executor_work_guard<net::io_context::executor_type>> guard_;
    std::thread th_;
};

} // namespace stratum_http_test
