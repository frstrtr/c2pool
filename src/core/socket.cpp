#include "socket.hpp"

namespace c2pool
{

void Socket::read_prefix(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->prefix[0], packet->prefix.size()),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                //TODO
            }

            // if (c2pool::dev::compare_str(packet->value.prefix, net->PREFIX, length))
            if (packet->prefix == m_node->m_prefix)
                read_command(packet);
            else {}
				// TODO: m_node->error(libp2p::BAD_PEER, "[socket] prefix doesn't match");
        }
    );
}

void Socket::read_command(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->command, 12),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                //TODO
            }

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
                //TODO
            }

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
                //TODO
            }

            read_payload(packet);
        }
    );
}

void Socket::read_payload(std::shared_ptr<Packet> packet)
{
    boost::asio::async_read(*m_socket, boost::asio::buffer(&packet->payload, packet->message_length),
        [this, packet](const auto& ec, std::size_t len)
        {
            if (ec)
            {
                //TODO
            }

            message_processing(packet);
            read();
        }
    );
}

void Socket::message_processing(std::shared_ptr<Packet> packet)
{
    // checksum 
    //TODO: check
    uint256 hash_checksum = Hash(std::span<std::byte>(packet->payload.data(), packet->payload.size()));
    if (hash_checksum.pn[7] != packet->checksum)
        std::cout << "ERROR CHECKSUM!" << std::endl;
        //TODO: Error Checksum
    
    auto msg = packet->to_message();
    m_node->handle(std::move(msg));
}


} // namespace c2pool