#include "socket.hpp"
#include <btclibs/util/strencodings.h>

namespace c2pool
{

void Socket::read_prefix(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->prefix[0], packet->prefix.size()),
        [this, packet](const auto& ec, std::size_t len)
        {
            std::cout << len << std::endl;
            if (ec)
            {
                std::cout << ec << " " << ec.message() << std::endl;
                return;
            }

            // if (c2pool::dev::compare_str(packet->value.prefix, net->PREFIX, length))
            if (packet->prefix == m_node->get_prefix())
            {
                std::cout << "[" << packet->prefix.size() << "] ";
                for (const auto& v : packet->prefix) std::cout << (int) v << " ";
                std::cout << std::endl;

                const auto& pref = m_node->get_prefix();
                std::cout << "[" << pref.size() << "] ";
                for (const auto& v : pref) std::cout << (int) v << " ";
                std::cout << std::endl;

                read_command(packet);
            }
            // else {}
				// TODO: m_node->error(libp2p::BAD_PEER, "[socket] prefix doesn't match");
        }
    );
}

void Socket::read_command(std::shared_ptr<Packet> packet)
{
    packet->command.resize(12);
    boost::asio::async_read(*m_socket, boost::asio::buffer(packet->command.data(), 12),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                std::cout << ec << " " << ec.message() << std::endl;
                return;
            }
            std::cout << "command: " << packet->command << std::endl;

            read_length(packet);
        }
    );
}

void Socket::read_length(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->message_length, sizeof(packet->message_length)),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                std::cout << ec << " " << ec.message() << std::endl;
                return;
            }
            std::cout << "message_length: " << packet->message_length << std::endl;
            packet->payload.resize(packet->message_length);
            read_checksum(packet);
        }
    );
}

void Socket::read_checksum(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->checksum, sizeof(packet->checksum)),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                std::cout << ec << " " << ec.message() << std::endl;
                return;
            }

            std::cout << "checksum: " << packet->checksum << std::endl;
            read_payload(packet);
        }
    );
}

void Socket::read_payload(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(packet->payload.data(), packet->message_length),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                std::cout << ec << " " << ec.message() << std::endl;
                return;
            }

            message_processing(packet);
            read();
        }
    );
}

void Socket::message_processing(std::shared_ptr<Packet> packet)
{
    // checksum 
    uint256 hash_checksum = Hash(std::span<std::byte>(packet->payload.data(), packet->payload.size()));
    if (hash_checksum.pn[0] != packet->checksum)
        std::cout << "ERROR CHECKSUM!: " << hash_checksum.pn[7] << "(" << hash_checksum.pn[0] << ") != " << packet->checksum  << std::endl;
        //TODO: Error Checksum
    
    auto msg = packet->to_message();
    m_node->handle(std::move(msg), m_addr);
}


} // namespace c2pool