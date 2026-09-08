// SPDX-License-Identifier: AGPL-3.0-or-later
#include "socket.hpp"
#include "factory.hpp"   // INetwork complete definition for weak_ptr<INetwork>::lock()
#include "log.hpp"
#include <btclibs/util/strencodings.h>

// Per-socket TCP liveness (keepalive + user-timeout). Linux-specific socket
// options are guarded by __linux__; the portable boost::asio keep_alive option
// is armed unconditionally. See Socket::init().
#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

namespace core
{

Socket::Socket(std::unique_ptr<boost::asio::ip::tcp::socket> socket,
               connection_type conn_type,
               ICommunicator* communicator,
               std::weak_ptr<INetwork> node_lifetime,
               bool was_managed)
    : m_socket(std::move(socket))
    , m_conn_type(conn_type)
    , m_node(communicator)
    , m_node_lifetime(std::move(node_lifetime))
    , m_was_managed(was_managed)
    , m_status(true)
{
}

bool Socket::acquire_node(std::shared_ptr<INetwork>& strong_out)
{
    strong_out = m_node_lifetime.lock();
    if (!m_was_managed) {
        // Unmanaged legacy node (LTC/DOGE pool pre-make_shared): no liveness
        // tracking available, fall back to raw m_node behavior. Returns true
        // unconditionally so the existing call path is preserved.
        return true;
    }
    // Managed node (Dash NodeP2P after c42d0f5c). lock() returning null
    // means the node has been freed mid-flight — abort the connection.
    return strong_out != nullptr;
}

void Socket::abort_connection()
{
    m_status = false;
    if (m_socket && m_socket->is_open()) {
        boost::system::error_code ec;
        m_socket->close(ec);
    }
}

// ASYNC_READ: every async-read callback locks the node lifetime at entry. If
// the node was managed and is now freed, the connection aborts cleanly without
// dereferencing m_node — preventing the Bug 9 / Bug-3-family UAF class.
//
// `strong_node` is in scope for the user-supplied `handler` and keeps the
// node alive for that scope's duration; m_node access inside the handler is
// safe.
#define ASYNC_READ(buffer, handler)\
    if (!m_status || !m_socket || !m_socket->is_open()) return;\
    boost::asio::async_read(*m_socket, buffer, [self = shared_from_this(), this, packet](const auto& ec, std::size_t len) {\
        if (!m_status) return; /* socket closed between dispatch and callback */\
        if (!ec) g_bytes_recv.fetch_add(len, std::memory_order_relaxed);\
        std::shared_ptr<INetwork> strong_node;\
        if (!acquire_node(strong_node)) {\
            LOG_DEBUG_OTHER << "Socket: aborting connection (node freed mid-flight)";\
            abort_connection();\
            return;\
        }\
        (void)strong_node; /* keeps node alive for handler scope */\
        handler\
    })

void Socket::init()
{
    // init addrs — guard against socket being closed before init() dispatched
    boost::system::error_code ec;
    auto ep_local  = m_socket->local_endpoint(ec);
    if (ec) { m_status = false; m_socket->close(); return; }
    auto ep_remote = m_socket->remote_endpoint(ec);
    if (ec) { m_status = false; m_socket->close(); return; }
    m_addr_local = NetService(ep_local);
    m_addr       = NetService(ep_remote);

    // ── Per-socket TCP liveness (pure transport; cannot corrupt protocol state).
    // Motivation: a stateful ISP-side per-flow DPI blackhole (TSPU-class CGN on
    // the hotel uplink) can silently wedge a flow both directions without ever
    // sending FIN/RST. is_open() never falsifies for such a half-open drop, so
    // a pending async_read/async_write can linger 15-30 min before anything
    // notices — the sharechain sync stalls for that whole window.
    //   * SO_KEEPALIVE (+ Linux 60/10/3 tuning) makes the kernel actively probe
    //     an idle path and error the pending op when it has gone dead (~90 s).
    //   * TCP_USER_TIMEOUT=30 s bounds how long UNACKED queued data may sit
    //     before the kernel aborts the connection — this is the fast path for a
    //     wedged (latched) flow: the write never ACKs, the socket errors in
    //     ~30 s, the peer is dropped, and the download loop redials over a
    //     FRESH connection (which gets a fresh DPI classifier budget).
    // This runs for ALL lanes (core), which is safe: keepalive + user-timeout
    // are liveness-only and never alter bytes on the wire. Best-effort — every
    // option is ignore-on-unsupported so non-Linux / restricted hosts still run.
    if (m_socket && m_socket->is_open()) {
        boost::system::error_code kec;
        m_socket->set_option(boost::asio::socket_base::keep_alive(true), kec); // portable (asio)
        if (kec)
            LOG_DEBUG_OTHER << "Socket::init: SO_KEEPALIVE set failed: " << kec.message();
#ifdef __linux__
        const int fd = m_socket->native_handle();
        int idle  = 60;   // seconds idle before first keepalive probe
        int intvl = 10;   // seconds between probes
        int cnt   = 3;    // failed probes before the connection is dropped (~90 s)
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
        // Abort a flow whose queued data stays unacknowledged for 30 s — the
        // DPI-latch fast path. Ignore-on-unsupported (older kernels).
        unsigned int usr_timeout_ms = 30000;
        ::setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &usr_timeout_ms, sizeof(usr_timeout_ms));
        LOG_TRACE << "Socket::init: TCP liveness armed (keepalive 60/10/3, user_timeout=30s)";
#endif
    }

    // start for reading socket data
    read();
}

void Socket::read()
{
    // Acquire the node before touching m_node->get_prefix() — without this,
    // a freed m_node returns garbage from get_prefix().size() and the Packet
    // ctor's prefix.resize() throws std::length_error (the original Bug 9
    // symptom). The Packet ctor's 16-byte cap from 0f91b499 stays as
    // belt-and-braces defense-in-depth.
    std::shared_ptr<INetwork> strong_node;
    if (!acquire_node(strong_node)) {
        LOG_DEBUG_OTHER << "Socket::read: aborting connection (node freed mid-flight)";
        abort_connection();
        return;
    }
    (void)strong_node;

    std::shared_ptr<Packet> packet;
    try {
        packet = std::make_shared<Packet>(m_node->get_prefix().size());
    } catch (const std::exception& e) {
        LOG_WARNING << "Socket::read: aborting connection (" << e.what() << ")";
        abort_connection();
        return;
    }
    read_prefix(packet);
}

void Socket::write(std::unique_ptr<RawMessage> msg_data)
{
    if (!m_status || !m_socket || !m_socket->is_open()) return;  // closed/disconnected

    // Acquire the node so get_prefix() and the error() callback don't UAF.
    std::shared_ptr<INetwork> strong_node;
    if (!acquire_node(strong_node)) {
        LOG_DEBUG_OTHER << "Socket::write: aborting (node freed mid-flight)";
        abort_connection();
        return;
    }

    auto packet = std::make_shared<PackStream>(Packet::from_message(m_node->get_prefix(), msg_data));

    // Queue, then start the drain ONLY if no composed write is in flight. The
    // framing is done here (on the caller's thread, as before) so the bytes are
    // captured in submission order; the wire order is then exactly the order in
    // which callers reached this line. See the m_write_queue comment in
    // socket.hpp for why overlapping composed writes cost shares.
    bool start_drain = false;
    {
        std::lock_guard<std::mutex> lock(m_write_mutex);
        m_write_queue.push_back(std::move(packet));
        if (!m_writing)
        {
            m_writing = true;
            start_drain = true;
        }
    }

    // Outside the lock: do_write() initiates asio work and must never run with
    // m_write_mutex held (leaf-lock discipline).
    if (start_drain)
        do_write();
}

void Socket::fail_write_queue()
{
    std::deque<std::shared_ptr<PackStream>> dropped;
    {
        std::lock_guard<std::mutex> lock(m_write_mutex);
        dropped.swap(m_write_queue);
        m_writing = false;
    }
    // `dropped` is released here, outside the lock.
}

void Socket::do_write()
{
    std::shared_ptr<PackStream> packet;
    {
        std::lock_guard<std::mutex> lock(m_write_mutex);
        if (m_write_queue.empty())
        {
            m_writing = false;
            return;
        }
        packet = m_write_queue.front();
    }

    // Socket closed under us between queueing and draining: fail the whole
    // chain rather than leave buffers pinned behind a stuck in-flight flag.
    // Matches the pre-queue behaviour, where write() on a closed socket was a
    // silent no-op with no error() callback.
    if (!m_status || !m_socket || !m_socket->is_open())
    {
        fail_write_queue();
        return;
    }

    boost::asio::async_write(*m_socket, boost::asio::buffer(packet->data(), packet->size()),
        [self = shared_from_this(), this, packet](const boost::system::error_code& ec, std::size_t length)
        {
            if (!ec) g_bytes_sent.fetch_add(length, std::memory_order_relaxed);
            if (ec) {
                // A failed write kills the connection, so everything still
                // queued behind it could never be delivered either: drop the
                // chain and report ONCE — exactly what a single failed write
                // did before the queue existed.
                fail_write_queue();
                std::shared_ptr<INetwork> strong;
                if (!acquire_node(strong)) {
                    abort_connection();
                    return;
                }
                m_node->error("Socket::write error: " + ec.message(), get_addr());
                return;
            }

            {
                std::lock_guard<std::mutex> lock(m_write_mutex);
                if (!m_write_queue.empty())
                    m_write_queue.pop_front();
            }
            // Start the NEXT composed write only from here — that ordering is
            // the whole point of the queue. Not unbounded recursion:
            // async_write never invokes its handler inline from the initiating
            // call, so each do_write() returns before the next one runs.
            do_write();
        }
    );
}

void Socket::read_prefix(std::shared_ptr<Packet> packet)
{
    ASYNC_READ(boost::asio::buffer(&packet->prefix[0], packet->prefix.size()),
        {
            if (ec)
            {
                m_node->error(ec, get_addr());
                return;
            }

            if (packet->prefix == m_node->get_prefix())
                read_command(packet);
            else
                m_node->error("prefix doesn't match", get_addr());
        }
    );
}

void Socket::read_command(std::shared_ptr<Packet> packet)
{
    packet->command.resize(12);
    ASYNC_READ(boost::asio::buffer(packet->command.data(), 12),
        {
            if (ec)
            {
                m_node->error(ec, get_addr());
                return;
            }
            // std::cout << "command: " << packet->command << std::endl;

            read_length(packet);
        }
    );
}

void Socket::read_length(std::shared_ptr<Packet> packet)
{
    ASYNC_READ(boost::asio::buffer(&packet->message_length, sizeof(packet->message_length)),
        {
            if (ec)
            {
                m_node->error(ec, get_addr());
                return;
            }
            // DoS cap: a malicious or corrupt peer can send a huge length here
            // and crash us with std::bad_alloc / std::length_error from the
            // payload resize. Bitcoin Core uses MAX_PROTOCOL_MESSAGE_LENGTH=4MiB;
            // we use 32MiB to accommodate Dash's larger mnlistdiff messages with
            // headroom. Disconnect cleanly on cap exceedance.
            constexpr uint32_t MAX_MESSAGE_LENGTH = 32u * 1024u * 1024u;
            if (packet->message_length > MAX_MESSAGE_LENGTH)
            {
                m_node->error("message_length " + std::to_string(packet->message_length)
                              + " exceeds cap " + std::to_string(MAX_MESSAGE_LENGTH),
                              get_addr());
                return;
            }
            packet->payload.resize(packet->message_length);
            read_checksum(packet);
        }
    );
}

void Socket::read_checksum(std::shared_ptr<Packet> packet)
{
    ASYNC_READ(boost::asio::buffer(&packet->checksum, sizeof(packet->checksum)),
        {
            if (ec)
            {
                m_node->error(ec, get_addr());
                return;
            }

            // std::cout << "checksum: " << packet->checksum << std::endl;
            read_payload(packet);
        }
    );
}

void Socket::read_payload(std::shared_ptr<Packet> packet)
{
    ASYNC_READ(boost::asio::buffer(packet->payload.data(), packet->message_length),
        {
            if (ec)
            {
                m_node->error(ec, get_addr());
                return;
            }

            message_processing(packet);
            read();
        }
    );
}

#undef ASYNC_READ

void Socket::message_processing(std::shared_ptr<Packet> packet)
{
    // checksum
    uint256 hash_checksum = Hash(std::span<std::byte>(packet->payload.data(), packet->payload.size()));
    if (hash_checksum.pn[0] != packet->checksum)
    {
        m_node->error("Socket::message_processing missmatch checksum!", get_addr());
        return;
    }

    auto msg = packet->to_message();
    m_node->handle(std::move(msg), m_addr);
}


} // namespace core