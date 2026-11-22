// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HTTP on the stratum port.
//
// python p2pool answered its web API on the worker port (9327 on LTC), and
// p2pool-aware trackers poll http://host:<worker port>/global_stats. c2pool
// answers it there too:
//
// - The stratum server reads the first line of a new connection. An HTTP
//   request line (METHOD SP target SP HTTP/1.x) hands the accepted socket,
//   with the bytes already read, to the web server's own HTTP session
//   (core::HttpSession) on the web server's HTTP thread: same routes, JSON and
//   headers, the real peer address on the socket. Anything else (a stratum
//   JSON line, garbage) takes the stratum path as before.
// - On the stratum port the session is read-only: GET and HEAD only (other
//   methods 405); no request is direct-local; every local-only, token-gated
//   or state-changing route answers 403 whatever the token; the event stream
//   answers 405; one response per connection.
// - --stratum-http=true|false|auto (default auto). auto is on only when the
//   stratum port reaches no interface the web server does not already listen
//   on (resolve_stratum_http): off for a web server bound to loopback, to one
//   LAN / VPN address while the stratum port binds wider or elsewhere, or to
//   0.0.0.0 while the stratum port binds an IPv6 address or ::.
//
// This header holds the pure pieces (mode, flag parse, resolution, sniff) and
// the hand-off record the stratum server passes to the web server.
#pragma once

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <core/log.hpp>

namespace core {

/// --stratum-http: On forces it on, Off forces it off, Auto follows the web
/// server's bind address (resolve_stratum_http).
enum class StratumHttpMode { Auto, On, Off };

inline const char* stratum_http_mode_name(StratumHttpMode m)
{
    switch (m) {
        case StratumHttpMode::On:  return "true";
        case StratumHttpMode::Off: return "false";
        default:                   return "auto";
    }
}

/// A --stratum-http value, from the command line or the settings file:
/// true / on / yes / 1, false / off / no / 0, or auto (any letter case).
/// false for anything else (out is left unchanged).
inline bool parse_stratum_http_value(std::string_view v, StratumHttpMode& out)
{
    std::string l(v);
    for (auto& c : l)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (l == "true" || l == "on" || l == "yes" || l == "1") {
        out = StratumHttpMode::On;
        return true;
    }
    if (l == "false" || l == "off" || l == "no" || l == "0") {
        out = StratumHttpMode::Off;
        return true;
    }
    if (l == "auto") {
        out = StratumHttpMode::Auto;
        return true;
    }
    return false;
}

/// One --stratum-http command-line token: "--stratum-http" (= true) or
/// "--stratum-http=<value>" (parse_stratum_http_value). false when the token
/// is not this flag or carries an unknown value (out is left unchanged).
inline bool parse_stratum_http_flag(std::string_view arg, StratumHttpMode& out)
{
    constexpr std::string_view kFlag = "--stratum-http";
    if (arg == kFlag) {
        out = StratumHttpMode::On;
        return true;
    }
    if (arg.size() <= kFlag.size() || arg.substr(0, kFlag.size()) != kFlag
        || arg[kFlag.size()] != '=')
        return false;
    return parse_stratum_http_value(arg.substr(kFlag.size() + 1), out);
}

/// The settings-file key stratum.http (its literal text): a value
/// parse_stratum_http_value knows sets `mode`; anything else is refused with
/// a warning and `mode` is left as it was (never silently turned off).
inline bool apply_stratum_http_setting(const std::string& value, StratumHttpMode& mode)
{
    if (parse_stratum_http_value(value, mode))
        return true;
    LOG_WARNING << "settings: stratum.http = '" << value
                << "' is not true, false or auto (or on/off/yes/no/1/0): ignored, "
                   "--stratum-http stays " << stratum_http_mode_name(mode);
    return false;
}

/// A bind host that only this machine can reach: "localhost", 127.0.0.0/8,
/// ::1, or an IPv4-mapped loopback address.
inline bool is_loopback_bind_host(const std::string& host)
{
    if (host == "localhost")
        return true;
    boost::system::error_code ec;
    const auto a = boost::asio::ip::make_address(host, ec);
    if (ec)
        return false;
    if (a.is_loopback())
        return true;
    if (a.is_v6() && a.to_v6().is_v4_mapped())
        return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, a.to_v6()).is_loopback();
    return false;
}

/// The process's --stratum-http, for coin mains whose stratum and web servers
/// are set up far from the command-line parse: the parse writes it, the
/// wiring (configure_stratum_http) reads it. Default auto.
inline StratumHttpMode& stratum_http_mode_setting()
{
    static StratumHttpMode mode = StratumHttpMode::Auto;
    return mode;
}

/// --stratum-http-budget and --stratum-http-per-ip (stratum_http_budget()).
struct StratumHttpLimits {
    std::size_t budget = 16;   // HTTP requests in progress at once (hand-offs)
    std::size_t per_ip = 6;    // of those, from one address (IPv6: one /64)
};

/// The process's --stratum-http-budget / --stratum-http-per-ip, written by the
/// parse and read by the wiring (configure_stratum_http). Defaults 16 and 6.
inline StratumHttpLimits& stratum_http_limits_setting()
{
    static StratumHttpLimits limits;
    return limits;
}

/// The hand-off budget in force for a connection cap.
struct StratumHttpBudget {
    std::size_t handoffs = 0;   // in progress at once, in total
    std::size_t per_key = 0;    // in progress at once, from one per_ip_cap_key
};

/// handoffs = min(budget, cap - 1) when cap > 0, and budget when cap = 0 (no
/// cap); budget 0 gives 0 either way (every HTTP request answered 503).
/// per_key = min(per_ip, handoffs); per_ip 0 gives handoffs.
inline StratumHttpBudget stratum_http_budget(std::size_t cap, std::size_t budget, std::size_t per_ip)
{
    StratumHttpBudget b;
    b.handoffs = cap == 0 ? budget : std::min(budget, cap - 1);
    b.per_key = per_ip == 0 ? b.handoffs : std::min(per_ip, b.handoffs);
    return b;
}

/// A --stratum-http-budget / --stratum-http-per-ip value: a decimal count
/// (digits only). false for anything else (out is left unchanged).
inline bool parse_stratum_http_count(std::string_view v, std::size_t& out)
{
    std::size_t n = 0;
    const auto r = std::from_chars(v.data(), v.data() + v.size(), n);
    if (v.empty() || r.ec != std::errc{} || r.ptr != v.data() + v.size())
        return false;
    out = n;
    return true;
}

/// The settings-file keys stratum.http_budget / stratum.http_per_ip: a count
/// of 0 or more sets `out`; anything else is refused with a warning and `out`
/// is left as it was.
inline bool apply_stratum_http_count_setting(const char* key, std::optional<int64_t> value,
                                             std::size_t& out)
{
    if (value && *value >= 0) {
        out = static_cast<std::size_t>(*value);
        return true;
    }
    LOG_WARNING << "settings: " << key << " is not a count of 0 or more: ignored, it stays " << out;
    return false;
}

struct StratumHttpDecision {
    bool on = false;          // the stratum port answers HTTP requests
    bool web = false;         // ... through the web server (false: a plain 503)
    std::string summary;      // for the startup line "stratum HTTP: <summary>"
};

/// What the stratum port does with an HTTP request, from --stratum-http, whether
/// the web server is listening, the address it is bound to, and the address
/// the stratum listener is bound to.
///   false -> OFF.  true -> ON (503 when there is no web server to answer).
///   auto  -> ON only when the stratum port reaches no interface the web
///            server does not already listen on, the web server not on
///            loopback: web bound to :: (every interface, IPv4 and IPv6); web
///            bound to 0.0.0.0 (every IPv4 interface) and the stratum
///            listener bound to an IPv4 address (or an IPv4-mapped one); or
///            both bound to the very same address. OFF when
///            the web server is loopback-only (a reverse proxy in front decides
///            what is public), bound to one LAN / VPN address while the stratum
///            port is bound wider or elsewhere, or disabled.
/// auto cannot see a firewall, a cloud security group or a container that
/// publishes only the stratum port: such a node sets true or false itself.
inline StratumHttpDecision resolve_stratum_http(StratumHttpMode mode, bool web_listening,
                                                const std::string& web_host,
                                                const std::string& stratum_host)
{
    StratumHttpDecision d;
    if (mode == StratumHttpMode::Off) {
        d.summary = "OFF (--stratum-http=false)";
        return d;
    }
    if (mode == StratumHttpMode::On) {
        d.on = true;
        d.web = web_listening;
        d.summary = web_listening
            ? "ON (--stratum-http=true; web bound to " + web_host + ")"
            : "ON (--stratum-http=true; web server disabled, HTTP requests are answered 503)";
        return d;
    }
    if (!web_listening) {
        d.summary = "OFF (web server disabled)";
        return d;
    }
    if (is_loopback_bind_host(web_host)) {
        d.summary = "OFF (web bound to " + web_host + " \xE2\x80\x94 proxy-only)";
        return d;
    }
    boost::system::error_code ec;
    const auto web_addr = boost::asio::ip::make_address(web_host, ec);
    if (ec) {
        d.summary = "OFF (web bind address '" + web_host + "' is not an IP address)";
        return d;
    }
    const std::string binds = stratum_host == web_host
        ? "web bound to " + web_host
        : "web bound to " + web_host + ", stratum to " + stratum_host;
    boost::system::error_code sec;
    const auto stratum_addr = boost::asio::ip::make_address(stratum_host, sec);
    if (!web_addr.is_unspecified()) {
        // One interface for the web server: the stratum port may serve its API
        // only on that same interface.
        if (sec || stratum_addr != web_addr) {
            d.summary = "OFF (" + binds + ")";
            return d;
        }
    } else if (web_addr.is_v4()) {
        // 0.0.0.0: every IPv4 interface, no IPv6 one. The stratum bind must be
        // IPv4 (or IPv4-mapped); :: and any other IPv6 bind is OFF.
        const bool v4 = !sec && (stratum_addr.is_v4()
                                 || (stratum_addr.is_v6() && stratum_addr.to_v6().is_v4_mapped()));
        if (!v4) {
            d.summary = "OFF (" + binds + ")";
            return d;
        }
    }
    d.on = true;
    d.web = true;
    d.summary = "ON (" + binds + ")";
    return d;
}

/// The first line of a connection (without its '\n'; a trailing '\r' is
/// allowed) is an HTTP/1.x request line: METHOD SP target SP HTTP/1.<digit>,
/// METHOD one of the RFC 9110 methods plus PATCH. A stratum JSON line starts
/// with '{' and never matches.
inline bool looks_like_http_request_line(std::string_view line)
{
    if (!line.empty() && line.back() == '\r')
        line.remove_suffix(1);
    static constexpr std::string_view kMethods[] = {
        "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT"};
    std::size_t sp = line.find(' ');
    if (sp == std::string_view::npos)
        return false;
    const std::string_view method = line.substr(0, sp);
    bool known = false;
    for (auto m : kMethods)
        known = known || method == m;
    if (!known)
        return false;
    const std::size_t sp2 = line.rfind(' ');
    if (sp2 <= sp + 1 || sp2 + 1 >= line.size())
        return false;   // no target, or no version
    const std::string_view version = line.substr(sp2 + 1);
    return version.size() == 8 && version.substr(0, 7) == "HTTP/1."
        && version[7] >= '0' && version[7] <= '9';
}

/// An HTTP connection the stratum server hands over: the accepted socket (on
/// the stratum io_context), the bytes it has already read from it, and its
/// slot under the stratum connection caps (released when the last owner drops
/// it: when the connection is closed).
struct StratumHttpRequest {
    using clock = std::chrono::steady_clock;
    boost::asio::ip::tcp::socket socket;
    std::string head;
    std::shared_ptr<void> slot;
    /// When the stratum server let go of the connection: the web server's
    /// read deadlines count from here.
    clock::time_point handed_off_at{};
    /// The stratum handshake deadline (StratumConfig::handshake_timeout_sec
    /// after the accept), nullopt for none: the end of the whole exchange
    /// (reading, writing, the slot). HttpSessionOptions::deadline.
    std::optional<clock::time_point> deadline;
    /// Called once with the request's method, target (query string removed)
    /// and response status; the stratum server logs it rate-limited.
    std::function<void(const std::string& method, const std::string& target, unsigned status)> on_response;
    /// Called when the request fails (malformed, cut off, timed out) with
    /// where and why; the stratum server logs it rate-limited.
    std::function<void(const std::string& what)> on_error;
};

/// The hand-off deadline's shutdown of one stratum-port HTTP connection,
/// shared by its HTTP session and a timer on the stratum io_context:
/// - fire() (the timer, at the hand-off deadline) shuts the descriptor down in
///   both directions, unless mark_closed() ran first;
/// - mark_closed() (the HTTP side, before it closes the socket) makes every
///   later fire() a no-op and cancels the timer;
/// - both take the same mutex; the descriptor is never duplicated or closed
///   here. The slot is released when the HTTP side closes the socket.
class StratumHttpDeadlineShutdown {
public:
    using native_handle_type = boost::asio::ip::tcp::socket::native_handle_type;

    explicit StratumHttpDeadlineShutdown(native_handle_type fd) : fd_(fd) {}

    /// The HTTP side, before it closes the socket. Idempotent.
    void mark_closed()
    {
        std::function<void()> cancel;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (closed_)
                return;
            closed_ = true;
            cancel = std::move(cancel_);
        }
        if (cancel)
            cancel();
    }

    /// At the hand-off deadline. true: the shutdown was issued.
    bool fire()
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (closed_)
            return false;
#ifdef _WIN32
        ::shutdown(fd_, SD_BOTH);
#else
        ::shutdown(fd_, SHUT_RDWR);
#endif
        ++shutdowns_;
        return true;
    }

    /// How mark_closed() cancels the timer; run at once when already closed.
    void set_cancel(std::function<void()> cancel)
    {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!closed_) {
                cancel_ = std::move(cancel);
                return;
            }
        }
        if (cancel)
            cancel();
    }

    bool closed() const
    {
        std::lock_guard<std::mutex> lk(mutex_);
        return closed_;
    }
    /// Shutdowns issued by fire() (0 or 1).
    uint64_t shutdowns() const
    {
        std::lock_guard<std::mutex> lk(mutex_);
        return shutdowns_;
    }

private:
    mutable std::mutex mutex_;
    const native_handle_type fd_;
    bool closed_ = false;
    uint64_t shutdowns_ = 0;
    std::function<void()> cancel_;
};

/// The 503 answer the stratum session writes itself is closed at
/// min(StratumHttpRequest::deadline, write start + this).
inline constexpr std::chrono::seconds kStratumHttpUnavailableWriteTimeout{30};

/// The stratum session's 503 bodies: NotServed (no web server, or it declined
/// the connection) and Busy (the hand-off budget or the per-address share is
/// in use).
enum class StratumHttpUnavailable { NotServed, Busy };
inline const char* stratum_http_unavailable_body(StratumHttpUnavailable kind)
{
    return kind == StratumHttpUnavailable::Busy
        ? R"({"error":"busy, try again later"})"
        : R"({"error":"the web API is not served on this node"})";
}

/// Takes the connection (moves req.socket out) and returns true, or returns
/// false and leaves it (the web server is not serving: the stratum session
/// answers 503 itself).
using StratumHttpHandler = std::function<bool(StratumHttpRequest& req)>;

} // namespace core
