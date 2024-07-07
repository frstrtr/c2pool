#pragma once

#include <memory>
#include <core/socket.hpp>


namespace c2pool
{
    
namespace pool
{

enum PeerConnectionType
{
    unknown,
    legacy,
    actual
};

template <typename Data>
class Peer : public Data
{
protected:
    PeerConnectionType connection_type {PeerConnectionType::unknown};
    std::shared_ptr<Socket> m_socket;

public:
    template <typename... Args>
    Peer(std::shared_ptr<Socket> socket, Args...) : m_socket(socket), Data(Args...) {}
};

} // namespace pool

} // namespace c2pool