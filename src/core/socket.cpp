#include "socket.hpp"
#include <btclibs/util/strencodings.h>

namespace core
{

#define ASYNC_READ(buffer, handler)\
    if (!m_status) return;\
    boost::asio::async_read(*m_socket, buffer, [this, packet](const auto& ec, std::size_t len) handler)

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
            // std::cout << "message_length: " << packet->message_length << std::endl;
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
        m_node->error("Socket::message_processing missmatch checksum!", get_addr());
        // std::cout << "ERROR CHECKSUM!: " << hash_checksum.pn[7] << "(" << hash_checksum.pn[0] << ") != " << packet->checksum  << std::endl;
    
    auto msg = packet->to_message();
    m_node->handle(std::move(msg), m_addr);
}


} // namespace core