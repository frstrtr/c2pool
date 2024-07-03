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

namespace c2pool
{

enum connection_type
{
    unknown,
    incoming,
    outgoing
};

/* Message header:
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class Packet
{
public:
    std::vector<std::byte> prefix;
    std::string command;
    uint32_t message_length;
    uint32_t checksum; // std::byte checksum[4];
    std::vector<std::byte> payload;

    // write
    static PackStream from_message(const std::vector<std::byte>& node_prefix, std::unique_ptr<RawMessage>& msg)
    {
        PackStream result(node_prefix);

        // command
        msg->m_command.resize(12);
        ArrayType<DefaultFormat, 12>::Write(result, msg->m_command);

        // message_length
        result << msg->m_data.size();

        // checksum
        //TODO: check
        uint256 hash_checksum = Hash(std::span<std::byte>(msg->m_data.data(), msg->m_data.size()));
        result << hash_checksum.pn[7];

        // payload
        result << msg->m_data;

        return result;
    }

    // read
    Packet(size_t prefix_length)
    {
        prefix.resize(prefix_length);
    }

    std::unique_ptr<RawMessage> to_message()
    {
        return std::make_unique<RawMessage>(command, PackStream(payload));
    }
};

class Socket
{
    std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;
    connection_type m_conn_type {unknown};
    INode* m_node {nullptr};

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
