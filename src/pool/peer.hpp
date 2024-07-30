#pragma once

#include <memory>
#include <core/timer.hpp>
#include <core/socket.hpp>
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
    std::shared_ptr<core::Socket> m_socket;

public:
    std::unique_ptr<core::Timer> m_timeout;

    // template <typename... Args>
    // Peer(std::shared_ptr<Socket> socket, Args... args) : m_socket(socket), Data(args...) {}

    Peer(std::shared_ptr<core::Socket> socket) : m_socket(socket) {}

    PeerConnectionType type() const { return connection_type; }
    void set_type(PeerConnectionType _type) { connection_type = _type; }

    void cancel()
    {
        m_socket->cancel();
    }

    void close()
    {
        m_socket->close();
    }

    void write(std::unique_ptr<RawMessage> rmsg)
    {
        m_socket->write(std::move(rmsg));
    }

    NetService addr() const
    {
        return m_socket->get_addr();
    }
};

} // namespace pool