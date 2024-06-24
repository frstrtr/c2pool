#pragma once

#include <map>
#include <vector>
#include <string>

#include <boost/asio.hpp>

#include <core/pack.hpp>
#include <core/message.hpp>
#include <core/handler.hpp>

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
    std::byte checksum[4];
    std::vector<std::byte> payload;

    // write
    static PackStream from_message(const std::vector<std::byte>& node_prefix, std::unique_ptr<RawMessage>& msg)
    {
        PackStream result(node_prefix);

        // prefix
        // result = node_prefix;

        // command
        msg->m_command.resize(12);
        ArrayType<std::byte, 12>::Write(result, msg->m_command);

        // message_length
        result << msg->m_data.size();

        // checksum
        // TODO:

        // payload
        result << msg->m_data;

        return result;
    }

    // read
    Packet(size_t prefix_length)
    {
        prefix.resize(prefix_length);
    }
};

class Socket
{
    IMessageHandler* m_handler {nullptr};
    std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;
    connection_type m_conn_type {unknown};
    std::vector<unsigned char> m_prefix;
private:
    


public:    
    Socket(std::unique_ptr<boost::asio::ip::tcp::socket> socket, connection_type conn_type, const std::vector<unsigned char>& prefix) : m_socket(std::move(socket)), m_conn_type(conn_type), m_prefix(prefix)
    {
       
    }

    void set_handler(IMessageHandler* handler)
    {
        if (handler)
            m_handler = handler;
    }

    connection_type type()
    {
        return m_conn_type;
    }

    void read()
    {

    }

    void write(std::unique_ptr<RawMessage> msg_data)
    {
        auto packet = std::make_unique<Packet>(m_prefix);
        // boost::asio::async_write(*m_socket, )
        
        boost::asio::async_write(*m_socket, boost::asio::buffer())
    }
};

} // namespace c2pool
