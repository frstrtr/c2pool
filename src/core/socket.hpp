#pragma once

#include <map>
#include <vector>
#include <string>
#include <source_location>

#include <boost/asio.hpp>

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/message.hpp>
#include <core/node_interface.hpp>
#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/packet.hpp>

namespace core
{

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
    ICommunicator* m_node {nullptr};
    bool m_status; // connected/disconnected

    NetService m_addr;
    NetService m_addr_local;

private:
    void read()
    {
        auto packet = std::make_shared<Packet>(m_node->get_prefix().size());
		read_prefix(packet);
    }

    void read_prefix(std::shared_ptr<Packet> packet);
	void read_command(std::shared_ptr<Packet> packet);
	void read_length(std::shared_ptr<Packet> packet);
	void read_checksum(std::shared_ptr<Packet> packet);
	void read_payload(std::shared_ptr<Packet> packet);
	void message_processing(std::shared_ptr<Packet> packet);

public:    
    Socket(std::unique_ptr<boost::asio::ip::tcp::socket> socket, connection_type conn_type, ICommunicator* node) : m_socket(std::move(socket)), m_conn_type(conn_type), m_node(node), m_status(true)
    {
    }

    void init()
    {
        // init addrs — guard against socket being closed before init() dispatched
        boost::system::error_code ec;
        auto ep_local  = m_socket->local_endpoint(ec);
        auto ep_remote = m_socket->remote_endpoint(ec);
        if (ec) { m_status = false; m_socket->close(); return; }
        m_addr_local = NetService(ep_local);
        m_addr       = NetService(ep_remote);

        // start for reading socket data
        read();
    }

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

    void write(std::unique_ptr<RawMessage> msg_data)
    {
        if (!m_status || !m_socket || !m_socket->is_open()) return;  // closed/disconnected
        auto packet = std::make_shared<PackStream>(Packet::from_message(m_node->get_prefix(), msg_data));
        boost::asio::async_write(*m_socket, boost::asio::buffer(packet->data(), packet->size()),
            [self = shared_from_this(), this, packet](const boost::system::error_code& ec, std::size_t length)
            {
                if (ec)
                {
                    m_node->error("Socket::write error: " + ec.message(), get_addr());
                }
            }
        );
    }
};

template <typename CommunicatorNode>
std::shared_ptr<core::Socket> make_socket(std::unique_ptr<boost::asio::ip::tcp::socket> tcp_socket, core::connection_type type, CommunicatorNode* node)
{
	auto communicator = dynamic_cast<core::ICommunicator*>(node);
	assert(communicator && "INetwork can't be cast to ICommunicator!");
	auto socket = std::make_shared<core::Socket>(std::move(tcp_socket), type, communicator);
    return socket;
}

} // namespace core
