#pragma once

#include <map>
#include <vector>
#include <string>

#include <boost/asio.hpp>

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/message.hpp>
#include <core/node_interface.hpp>
#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/packet.hpp>

namespace c2pool
{

enum connection_type
{
    unknown,
    incoming,
    outgoing
};

class Socket
{
    std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;
    connection_type m_conn_type {unknown};
    INode* m_node {nullptr};

    NetService m_addr;
    NetService m_addr_local;
private:

    void read()
    {
        auto packet = std::make_shared<Packet>(m_node->m_prefix.size());
		read_prefix(packet);
    }

    void read_prefix(std::shared_ptr<Packet> packet);
	void read_command(std::shared_ptr<Packet> packet);
	void read_length(std::shared_ptr<Packet> packet);
	void read_checksum(std::shared_ptr<Packet> packet);
	void read_payload(std::shared_ptr<Packet> packet);
	void message_processing(std::shared_ptr<Packet> packet);

public:    
    Socket(std::unique_ptr<boost::asio::ip::tcp::socket> socket, connection_type conn_type, INode* node) : m_socket(std::move(socket)), m_conn_type(conn_type), m_node(node)
    {
        read(); // start for reading socket data
    }

    connection_type type()
    {
        return m_conn_type;
    }

    void write(std::unique_ptr<RawMessage> msg_data)
    {
        auto packet = Packet::from_message(m_node->m_prefix, msg_data);
        
        boost::asio::async_write(*m_socket, boost::asio::buffer(packet.data(), packet.size()),
            [this, packet](const boost::system::error_code& ec, std::size_t length)
            {
                if (ec)
                {
                    //TODO: error
                }

                // message received
            }
        );
    }
};

} // namespace c2pool
