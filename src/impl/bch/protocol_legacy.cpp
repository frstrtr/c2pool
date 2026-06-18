// BCH legacy-protocol dispatch router (broadcaster-gate / pool p2p ingress).
//
// Mirror of btc::Legacy::handle_message with the namespace swapped to bch.
// Conformance anchor: p2poolBCH @6603b79 + btc oracle protocol_legacy.cpp.
// Routing contract (matches oracle exactly, the thing reviewers diff):
//   parse RawMessage via m_handler -> std::visit-dispatch to the typed
//   handle(msg, peer) HANDLER overload for the command. Unknown/over-old
//   peers are gated upstream by NodeBridge via handle_version (require-version
//   before any command routes here). Parse and handler faults are logged and
//   swallowed per-message — never tear down the peer loop on one bad frame.
//
// Router skeleton (handle_message) + peer-book HANDLER cluster
// (addrs/addrme/ping/getaddrs) land here; share/tx HANDLER bodies
// (shares/sharereq/...) follow in later slices.
#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

namespace bch
{

void Legacy::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    bch::Handler::result_t result;
    try
    {
        result = m_handler.parse(rmsg);
    } catch (const std::exception& ec)
    {
        LOG_WARNING << "Failed to parse message '" << rmsg->m_command << "' from "
                    << peer->addr().to_string() << ": " << ec.what();
        return;
    }

    try
    {
        std::visit([&](auto& msg){ handle(std::move(msg), peer); }, result);
    }
    catch (const std::exception& ec)
    {
        LOG_WARNING << "Handler error for '" << rmsg->m_command << "' from "
                    << peer->addr().to_string() << ": " << ec.what();
        return;
    }
}

// ---------------------------------------------------------------------------
// Peer-book HANDLER cluster (addrs / addrme / ping / getaddrs).
//
// Mechanical mirror of btc::Legacy peer-book handlers (oracle protocol_legacy
// .cpp), namespace-swapped btc -> bch. Pure pool-p2p address-book maintenance:
// gossip-relay learned peers, answer getaddrs from get_good_peers, no-op ping.
// p2pool-merged-v36 surface: NONE (no share / PPLNS / coinbase / AuxPoW bytes;
// peer discovery only). Share/tx HANDLER bodies (shares/sharereq/...) follow in
// later slices; routed via the same std::visit dispatcher in handle_message().
// ---------------------------------------------------------------------------

void Legacy::HANDLER(addrs)
{
    for (auto& addr : msg->m_addrs)
    {
        addr.m_timestamp = std::min((uint64_t) core::timestamp(), addr.m_timestamp);
        got_addr(addr.m_endpoint, addr.m_services, addr.m_timestamp);

        if ((core::random::random_float(0, 1) < 0.8) && (!m_connections.empty()))
        {
            auto wpeer = core::random::random_choice(m_connections);
            auto rmsg = bch::message_addrs::make_raw({addr});
            wpeer->write(std::move(rmsg));
        }
    }
}

void Legacy::HANDLER(addrme)
{
    if (peer->addr().address() == "127.0.0.0")
    {
        if (m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = bch::message_addrme::make_raw(msg->m_port);
            random_peer->write(std::move(rmsg));
        }
    } else
    {
        auto endpoint = NetService{peer->addr().address(), msg->m_port};
        got_addr(endpoint, peer->m_other_services, core::timestamp());
        if (m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = bch::message_addrs::make_raw({addr_record_t{peer->m_other_services, endpoint, core::timestamp()} });
            random_peer->write(std::move(rmsg));
        }
    }
}

void Legacy::HANDLER(ping)
{
}

void Legacy::HANDLER(getaddrs)
{
    if (msg->m_count > 100)
        msg->m_count = 100;

    std::vector<addr_record_t> addrs;
    for (const auto& pair : get_good_peers(msg->m_count))
    {
        addrs.push_back({pair.value.m_service, pair.addr, pair.value.m_last_seen});
    }

    auto rmsg = bch::message_addrs::make_raw({addrs});
    peer->write(std::move(rmsg));
}


} // namespace bch
