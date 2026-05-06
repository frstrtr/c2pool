#pragma once

#include <memory>

namespace core
{

// Forward-declared so this header doesn't pull socket.hpp (which needs
// INetwork's definition for the make_socket template — that's the
// circular we're avoiding by extracting INetwork here).
struct Socket;

// Bug 3 root-cause-fix support type. Network nodes that are managed by
// shared_ptr (the common case) inherit from INetwork so the Factory's
// async lambdas can capture a weak_ptr<INetwork> via weak_from_this()
// instead of a raw pointer that may dangle when the node disconnects
// mid-handshake. Nodes that aren't shared_ptr-managed get a default-
// constructed weak_ptr (locks to nullptr) and the Factory falls back to
// the raw m_node pointer — preserves prior behavior for callers not
// affected by the disconnect-reconnect cascade.
struct INetwork : public std::enable_shared_from_this<INetwork>
{
    virtual ~INetwork() = default;
    virtual void connected(std::shared_ptr<core::Socket> socket) = 0;
    virtual void disconnect() = 0;
};

} // namespace core
