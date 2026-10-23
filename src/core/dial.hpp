// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// == #965 Phase-3: outbound dial across address families =======================
//
// core::Factory's Client resolves a peer with ONE async_resolve(host, port) --
// protocol unspecified, so getaddrinfo(AF_UNSPEC, AI_ADDRCONFIG) already returns
// BOTH the A and the AAAA records on a host that has a configured address of
// each family -- and then handed the whole list to boost::asio's range
// async_connect. That loop is sequential with NO per-attempt deadline: when the
// first endpoint is an AAAA whose path is blackholed (a v6 address that is
// configured but not routed -- common on v6-primary/NAT'd hosts, the #963/#965
// hotel shape), the attempt sits in kernel SYN retransmits (~127 s at the Linux
// default tcp_syn_retries=6) before the A record is ever tried. On every
// reconnect, again, because nothing remembers which family worked.
//
// This header adds the two missing pieces, and nothing else:
//
//   order_dial_endpoints()  RFC 8305 s.4 family interleave, led by the family
//                           that last connected to this host (prior success,
//                           core::preferred_dial_family). Within a family the
//                           resolver's own (RFC 6724) order is kept.
//   dial_endpoints()        sequential dial; when -- and ONLY when -- the list
//                           holds both families, every attempt except the last
//                           gets a deadline, so a hung family falls through to
//                           the other one instead of stalling the dial.
//
// v4-only hosts: AI_ADDRCONFIG suppresses AAAA there, so the list is A-only.
// A single-family list is returned by order_dial_endpoints() UNCHANGED and
// dial_endpoints() hands it to the same boost::asio range async_connect the
// Client called before this change -- same endpoints, same order, no timer, no
// new state written. Nothing on the wire changes on any host: this is transport
// only, and the #910 wire memo (A records only) is untouched.
//
// Deliberately NOT parallel happy-eyeballs racing: one socket, one attempt in
// flight, so the node's connection accounting sees exactly one outbound dial
// per connect() exactly as before.

#include <core/log.hpp>
#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace core
{

/// Per-attempt deadline for a mixed-family dial (all attempts but the last).
/// Covers the SYN plus two retransmits (1 s, 3 s) -- a live path answers well
/// inside it; a blackholed one is abandoned for the other family.
inline constexpr std::chrono::milliseconds FAMILY_FALLBACK_ATTEMPT_TIMEOUT{5000};

/// v4-mapped (::ffff:a.b.c.d) is an IPv4 destination, not a v6 one.
inline DialFamily dial_family_of(const boost::asio::ip::address& a)
{
    if (a.is_v6() && !a.to_v6().is_v4_mapped())
        return DialFamily::V6;
    return DialFamily::V4;
}

inline const char* dial_family_name(DialFamily f)
{
    return f == DialFamily::V6 ? "v6" : "v4";
}

inline bool is_mixed_family(const std::vector<boost::asio::ip::tcp::endpoint>& eps)
{
    for (const auto& ep : eps)
        if (dial_family_of(ep.address()) != dial_family_of(eps.front().address()))
            return true;
    return false;
}

/// RFC 8305 s.4 ordering. Single-family input is returned unchanged.
/// Mixed input: alternate families, starting with `preferred` (the family that
/// last connected to this host) when given, else with the resolver's first
/// entry's family; each family keeps the resolver's relative order.
inline std::vector<boost::asio::ip::tcp::endpoint>
order_dial_endpoints(std::vector<boost::asio::ip::tcp::endpoint> eps,
                     std::optional<DialFamily> preferred)
{
    if (eps.empty() || !is_mixed_family(eps))
        return eps;

    std::vector<boost::asio::ip::tcp::endpoint> v4, v6;
    for (auto& ep : eps)
        (dial_family_of(ep.address()) == DialFamily::V6 ? v6 : v4).push_back(ep);

    const DialFamily lead = preferred.value_or(dial_family_of(eps.front().address()));
    auto& first  = (lead == DialFamily::V6) ? v6 : v4;
    auto& second = (lead == DialFamily::V6) ? v4 : v6;

    std::vector<boost::asio::ip::tcp::endpoint> out;
    out.reserve(eps.size());
    for (size_t i = 0; i < first.size() || i < second.size(); ++i)
    {
        if (i < first.size())  out.push_back(first[i]);
        if (i < second.size()) out.push_back(second[i]);
    }
    return out;
}

namespace detail
{

template <typename Handler>
struct StagedDial : std::enable_shared_from_this<StagedDial<Handler>>
{
    boost::asio::ip::tcp::socket& socket;
    boost::asio::steady_timer timer;
    std::vector<boost::asio::ip::tcp::endpoint> eps;
    std::chrono::steady_clock::duration attempt_timeout;
    std::string label;
    Handler handler;
    size_t idx = 0;
    bool timed_out = false;
    boost::system::error_code last_ec;

    StagedDial(boost::asio::ip::tcp::socket& s,
               std::vector<boost::asio::ip::tcp::endpoint> e,
               std::chrono::steady_clock::duration t, std::string l, Handler h)
        : socket(s), timer(s.get_executor()), eps(std::move(e)),
          attempt_timeout(t), label(std::move(l)), handler(std::move(h)) {}

    void attempt()
    {
        if (idx >= eps.size())
        {
            handler(last_ec ? last_ec : boost::asio::error::not_found,
                    boost::asio::ip::tcp::endpoint{});
            return;
        }

        boost::system::error_code ignored;
        socket.close(ignored);  // async_connect re-opens with eps[idx].protocol()
        timed_out = false;

        auto self = this->shared_from_this();
        if (idx + 1 < eps.size())
        {
            timer.expires_after(attempt_timeout);
            timer.async_wait([self](const boost::system::error_code& ec)
            {
                if (ec)
                    return;  // cancelled: the attempt finished first
                self->timed_out = true;
                boost::system::error_code ig;
                self->socket.close(ig);  // aborts the pending connect
            });
        }

        socket.async_connect(eps[idx], [self](const boost::system::error_code& ec)
        {
            self->timer.cancel();

            // timed_out is checked FIRST: if the deadline fired after the
            // connect had already completed but before this handler ran, the
            // socket has been closed under it -- that is a timeout, not a win.
            if (!self->timed_out)
            {
                if (!ec)
                {
                    self->handler(ec, self->eps[self->idx]);
                    return;
                }
                // Genuine cancellation (teardown / ioc.stop()): stop dialling and
                // report it exactly as the range async_connect would have.
                if (ec == boost::asio::error::operation_aborted)
                {
                    self->handler(ec, boost::asio::ip::tcp::endpoint{});
                    return;
                }
            }

            self->last_ec = self->timed_out
                ? boost::system::error_code(boost::asio::error::timed_out)
                : ec;

            const auto& failed = self->eps[self->idx];
            ++self->idx;
            if (self->idx < self->eps.size()
                && dial_family_of(self->eps[self->idx].address())
                   != dial_family_of(failed.address()))
            {
                LOG_INFO << "[" << self->label << "] dial "
                         << dial_family_name(dial_family_of(failed.address()))
                         << " " << failed << " failed (" << self->last_ec.message()
                         << "); falling back to "
                         << dial_family_name(dial_family_of(self->eps[self->idx].address()))
                         << " " << self->eps[self->idx];
            }
            self->attempt();
        });
    }
};

} // namespace detail

/// Dial `eps` in order on `socket`; `handler(error_code, endpoint)` is called
/// once, with the endpoint that connected (or a default one on failure).
///
/// Single-family list -> boost::asio range async_connect, exactly the pre-#965
/// path (no deadline). Mixed list -> staged dial with `attempt_timeout` on every
/// attempt but the last. The caller keeps `socket` alive (Client captures its
/// shared Socket in `handler`). Single-threaded executor assumed, as for the
/// rest of Client.
template <typename Handler>
void dial_endpoints(boost::asio::ip::tcp::socket& socket,
                    std::vector<boost::asio::ip::tcp::endpoint> eps,
                    std::chrono::steady_clock::duration attempt_timeout,
                    const std::string& label,
                    Handler&& handler)
{
    if (eps.empty() || !is_mixed_family(eps))
    {
        boost::asio::async_connect(socket, std::move(eps), std::forward<Handler>(handler));
        return;
    }
    auto dial = std::make_shared<detail::StagedDial<std::decay_t<Handler>>>(
        socket, std::move(eps), attempt_timeout, label, std::forward<Handler>(handler));
    dial->attempt();
}

} // namespace core
