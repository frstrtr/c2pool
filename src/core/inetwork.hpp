#pragma once

#include <memory>

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
};

} // namespace core
