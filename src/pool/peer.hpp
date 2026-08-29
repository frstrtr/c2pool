// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <memory>
#include <core/log.hpp>
#include <core/p2p_message_stats.hpp>
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

    /// SEND choke point for the pool protocol. EVERY outbound pool message in
    /// every coin lane goes through here (verified: the only other
    /// Socket::write callers are the coin-daemon p2p connections, a different
    /// protocol), which is why the outbound counter lives here and not in the
    /// per-coin protocol files.
    ///
    /// Observe-only: the counter is a relaxed fetch_add and the message is
    /// forwarded byte-unchanged.
    void write(std::unique_ptr<RawMessage> rmsg)
    {
        if (rmsg)
        {
            auto& stats = core::obs::p2p_stats();
            stats.count_out(rmsg->m_command);
            // Off by default; nothing in-tree enables it. Counters are the
            // hot-path mechanism, this is the opt-in magnifying glass.
            if (stats.trace_enabled.load(std::memory_order_relaxed))
                LOG_DEBUG_POOL << "[p2p-msg] out "
                               << std::string(core::obs::trim_command(rmsg->m_command))
                               << " -> " << m_socket->get_addr().to_string();
        }
        m_socket->write(std::move(rmsg));
    }

    void stable(PeerConnectionType type, time_t new_timeout_time)
    {
        set_type(type);
        m_timeout->restart(new_timeout_time); // change timeout, example: 10s -> 100s
    }

    NetService addr() const
    {
        return m_socket->get_addr();
    }
};

} // namespace pool