// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <deque>
#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <memory>
#include <source_location>

#include <boost/asio.hpp>

#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/message.hpp>
#include <core/node_interface.hpp>
#include <core/inetwork.hpp>
#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/packet.hpp>

namespace core
{

// INetwork is defined in core/inetwork.hpp (included above) so the make_socket
// template below sees its complete type for the dynamic_cast + weak_from_this().

enum connection_type
{
    unknown,
    incoming,
    outgoing
};

// for handle message/error from network
struct ICommunicator
{
    using message_error_type = std::string;

    virtual void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
    virtual void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
    virtual void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) = 0;
    virtual const std::vector<std::byte>& get_prefix() const = 0;
};

class Socket : public std::enable_shared_from_this<Socket>
{
    std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;
    connection_type m_conn_type {unknown};

    // Node lifetime tracking — fundamental fix for the Bug 9 / Bug-3-family
    // UAF class (see frstrtr/the/docs/c2pool-socket-lifecycle-fundamental-fix.md).
    //
    // m_node is the raw ICommunicator* used for fast access in async callbacks.
    // m_node_lifetime is a weak_ptr to the same object's INetwork interface,
    // which tracks the underlying lifetime via enable_shared_from_this. At
    // every async-callback entry, we lock m_node_lifetime; if the node has
    // been freed mid-flight (returns null AND was_managed is true), we abort
    // the connection cleanly instead of dereferencing m_node and crashing.
    //
    // m_was_managed records whether the node was shared_ptr-managed at
    // construction time. For unmanaged nodes (legacy LTC/DOGE pool pattern,
    // not migrated to make_shared yet), weak_ptr.lock() always returns null
    // but was_managed is false, so the lock-or-bail check is skipped and
    // behavior matches the pre-fix raw-pointer code. This keeps LTC mainnet
    // pool unchanged while the Dash side gets the fix.
    ICommunicator*           m_node {nullptr};
    std::weak_ptr<INetwork>  m_node_lifetime;
    bool                     m_was_managed {false};

    bool m_status; // connected/disconnected

    NetService m_addr;
    NetService m_addr_local;

    // ── Outbound write queue (issue #863) ──────────────────────────────────
    //
    // Asio forbids initiating a second COMPOSED write on a descriptor before
    // the first one completes: the two async_write_some continuations are
    // serviced FIFO per descriptor, so a message needing more than one round
    // gets bytes from the other message spliced into its middle. The peer then
    // sees a bad length/checksum and drops the connection.
    //
    // Every coin's send_shares issues three back-to-back writes on one socket
    // in a single handler turn (remember_tx -> shares -> forget_tx), and
    // handle_version writes getaddrs/addrme before the (potentially ~32 KB)
    // have_tx advert. Because send_shares reports its hashes as "sent" on
    // SUBMISSION and broadcast_share never retries, a spliced frame loses that
    // share to that peer permanently — silent PPLNS loss.
    //
    // Fix: buffer composed writes here and drain strictly in submission order,
    // starting the next one only from the previous completion handler, so at
    // most ONE composed async_write is ever in flight per socket. Same shape as
    // StratumSession::send_response/do_write (core/stratum_server.cpp).
    //
    // m_write_mutex is a LEAF lock: it is only ever held around the deque/flag
    // mutation and is never held across async_write initiation, an m_node
    // callback, or any other lock — writes are submitted from node/compute
    // threads as well as from the io_context thread, so the queue itself must
    // be guarded, but no new lock-order edge is introduced.
    //
    // Deliberately UNCAPPED, unlike StratumSession's backlog cap: before this
    // queue existed a stalled peer already pinned one PackStream per
    // overlapping in-flight async_write, so the memory profile is unchanged,
    // and dropping a queued p2p message would reintroduce exactly the silent
    // share loss this fixes. A stuck peer is still reaped by the existing
    // read-side error path.
    mutable std::mutex m_write_mutex;
    std::deque<std::shared_ptr<PackStream>> m_write_queue;
    bool m_writing {false}; // true while a composed async_write is in flight

public:
    // Global P2P traffic counters (all sockets combined)
    static inline std::atomic<uint64_t> g_bytes_recv{0};
    static inline std::atomic<uint64_t> g_bytes_sent{0};

private:
    // Lock the node lifetime. Returns true if it's safe to use m_node:
    //   - was_managed=false (unmanaged legacy node) → always returns true
    //   - was_managed=true and lock succeeded → returns true; strong_out
    //     keeps the node alive for the duration of the caller's scope
    //   - was_managed=true and lock returned null → returns false; the node
    //     has been freed mid-flight, the connection should abort
    // Defined out-of-line in socket.cpp where INetwork is complete.
    bool acquire_node(std::shared_ptr<INetwork>& strong_out);

    // Cleanly abort the connection without dereferencing m_node (used when
    // acquire_node fails). Also called from the Bug 9 Packet-cap path.
    void abort_connection();

    void read();   // moved out-of-line; needs INetwork complete via acquire_node

    // Drain step of the outbound queue: initiates the composed async_write for
    // the front element and re-arms itself from that write's completion
    // handler. Never called while another composed write is in flight.
    void do_write();

    // Drop every still-queued buffer and clear the in-flight flag. Used on
    // write error / closed socket so the whole queued chain fails together,
    // exactly as the single pre-queue write failed as a unit.
    void fail_write_queue();

    void read_prefix(std::shared_ptr<Packet> packet);
	void read_command(std::shared_ptr<Packet> packet);
	void read_length(std::shared_ptr<Packet> packet);
	void read_checksum(std::shared_ptr<Packet> packet);
	void read_payload(std::shared_ptr<Packet> packet);
	void message_processing(std::shared_ptr<Packet> packet);

public:
    // Defined out-of-line in socket.cpp; needs INetwork complete to construct
    // the weak_ptr from a shared_ptr<INetwork>.
    Socket(std::unique_ptr<boost::asio::ip::tcp::socket> socket,
           connection_type conn_type,
           ICommunicator* communicator,
           std::weak_ptr<INetwork> node_lifetime,
           bool was_managed);

    void init();   // out-of-line; calls read() which needs acquire_node

    connection_type type()
    {
        return m_conn_type;
    }

    const NetService& get_addr() const
    {
        return m_addr;
    }

    bool status() const
    {
        return m_status;
    }

    void cancel()
    {
        m_status = false;
        boost::system::error_code ec;
        m_socket->cancel(ec);
        // ignore ec: canceling a reset/closed socket is benign
    }

    void close()
    {
        m_status = false;
        boost::system::error_code ec;
        m_socket->close(ec);
        // ignore ec: closing an already-closed socket is benign
    }

    auto raw()
    {
        return m_socket.get();
    }
    //=====================

    void write(std::unique_ptr<RawMessage> msg_data);  // out-of-line; uses acquire_node
};

// Construct a Socket. Computes the weak_ptr<INetwork> liveness tracker from
// the node's shared_from_this() if it's shared_ptr-managed (modern Dash node
// pattern after c42d0f5c), or stores an empty weak_ptr + was_managed=false
// for legacy unmanaged nodes (LTC/DOGE pool today).
//
// Defined inline as a template so the caller's full INetwork type is
// available for the dynamic_cast + weak_from_this() call.
template <typename CommunicatorNode>
std::shared_ptr<core::Socket> make_socket(
    std::unique_ptr<boost::asio::ip::tcp::socket> tcp_socket,
    core::connection_type type,
    CommunicatorNode* node)
{
    auto communicator = dynamic_cast<core::ICommunicator*>(node);
    assert(communicator && "node can't be cast to ICommunicator!");
    auto network = dynamic_cast<core::INetwork*>(node);
    std::weak_ptr<core::INetwork> weak_node;
    bool was_managed = false;
    if (network) {
        weak_node = network->weak_from_this();
        was_managed = (weak_node.lock() != nullptr);
    }
    return std::make_shared<core::Socket>(
        std::move(tcp_socket), type, communicator,
        std::move(weak_node), was_managed);
}

} // namespace core