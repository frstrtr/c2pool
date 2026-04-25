#include "socket.hpp"
#include "log.hpp"
#include <btclibs/util/strencodings.h>

namespace core
{

#define ASYNC_READ(buffer, handler)\
    if (!m_status || !m_socket || !m_socket->is_open()) return;\
    boost::asio::async_read(*m_socket, buffer, [self = shared_from_this(), this, packet](const auto& ec, std::size_t len) {\
        if (!m_status) return; /* socket closed between dispatch and callback */\
        if (!ec) g_bytes_recv.fetch_add(len, std::memory_order_relaxed);\
        handler\
    })

void Socket::read_prefix(std::shared_ptr<Packet> packet)
{
    // if (!m_status) return;
    // // auto ptr = shared_from_this();
    // boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->prefix[0], packet->prefix.size()),
    //     [this/*, ptr = ptr*/, packet](const auto& ec, std::size_t len)
    //     {
    //         if (ec)
    //         {
    //             m_node->error(ec, get_addr());
    //             return;
    //         }

    //         if (packet->prefix == m_node->get_prefix())
    //             read_command(packet);
    //         else
    //             m_node->error("prefix doesn't match", get_addr());
    //     }
    // );

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