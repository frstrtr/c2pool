// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <memory>

// Forward declaration (global namespace): the outbound dial-failure hook below
// takes a NetService by const-ref. Only the declaration is needed here — the
// coin-layer overriders and the Factory caller already include the full
// core/netaddress.hpp. Keeps inetwork.hpp free of that heavy header.
class NetService;

namespace core
{
// Forward declaration: INetwork only needs Socket as an incomplete type for the
// shared_ptr in connected(); the full Socket definition lives in socket.hpp.
class Socket;

// Bug 3 root-cause fix: INetwork inherits enable_shared_from_this so
// Factory::Client / Factory::Server can capture weak_from_this() into
// their async lambdas instead of raw `this`. When the derived node
// (e.g. dash::coin::p2p::NodeP2P) is owned by a shared_ptr, the captured
// weak_ptr keeps it alive across the async callback's execution, fixing
// the use-after-free that produced the 19:23:15 UTC SIGSEGV in
// codecvt::do_length called from the boost::log formatter inside
// NodeP2P::connected on a freed m_target_addr.
//
// For derived nodes NOT owned by shared_ptr (current LTC/DOGE pattern),
// weak_from_this() returns an empty weak_ptr; Factory falls back to the
// raw m_node pointer (preserves prior behavior — LTC/DOGE haven't been
// observed to crash, the disconnect-reconnect cascade is Dash-specific).
//
// Lives in its own header (not factory.hpp) so socket.hpp can include the full
// definition: make_socket() dynamic_casts to INetwork* and calls
// weak_from_this(), both of which require a complete type. AppleClang/MSVC
// diagnose the incomplete forward-declared type at template-parse time where
// GNU ld-era GCC tolerated it.
struct INetwork : public std::enable_shared_from_this<INetwork>
{
    virtual ~INetwork() = default;
    virtual void connected(std::shared_ptr<core::Socket> socket) = 0;
    virtual void disconnect() = 0;

    // Outbound dial-failure hook — fired by Factory::Client when an outbound
    // connect (or its DNS resolve) fails BEFORE connected() ever runs (the
    // socket never came up: ECONNREFUSED / ETIMEDOUT / resolve error). Default
    // no-op so existing nodes (LTC/DOGE/merged) are unaffected; the DASH-isolated
    // CoinClient overrides it to feed the dead target into the CoinPeerManager
    // scorer. Without this, dial failures never reach the scorer, so the same
    // top-scored dead seeds are re-selected on every refresh forever (#940).
    virtual void connect_failed(const ::NetService& /*addr*/) {}
};

} // namespace core