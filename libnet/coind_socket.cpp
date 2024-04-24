#include "coind_socket.h"

#include <libp2p/socket_packet.h>
#include <libdevcore/str.h>

#include <boost/asio.hpp>

// Read
void CoindSocket::read_prefix(SocketPacket<ReadPacket>::ptr_type packet)
{
	boost::asio::async_read(*socket, boost::asio::buffer(packet->value.prefix, net->PREFIX_LENGTH),
		[this, packet](boost::system::error_code ec, std::size_t length)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_prefix (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_COIND << "PoolSocket::read_prefix canceled";
				return;
			}

			if (c2pool::dev::compare_str(packet->value.prefix, net->PREFIX, length))
                read_command(packet);
            else
				error(libp2p::BAD_PEER, "[socket] prefix doesn't match");
		}
	);
}

void CoindSocket::read_command(SocketPacket<ReadPacket>::ptr_type packet)
{
	boost::asio::async_read(*socket, boost::asio::buffer(packet->value.command, packet->value.COMMAND_LEN),
		[this, packet](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_command (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_COIND << "CoindSocket::read_command canceled";
				return;
			}

			read_length(packet);
		}
	);
}

void CoindSocket::read_length(SocketPacket<ReadPacket>::ptr_type packet)
{
	boost::asio::async_read(*socket, boost::asio::buffer(packet->value.len, packet->value.LEN_LEN),
		[this, packet](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_length (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_COIND << "CoindSocket::read_length canceled";
				return;
			}

			read_checksum(packet);
		}
	);
}

void CoindSocket::read_checksum(SocketPacket<ReadPacket>::ptr_type packet)
{
	boost::asio::async_read(*socket, boost::asio::buffer(packet->value.checksum, packet->value.CHECKSUM_LEN),
		[this, packet](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_checksum (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_COIND << "CoindSocket::read_checksum canceled";
				return;
			}

			read_payload(packet);
		}
	);
}

void CoindSocket::read_payload(SocketPacket<ReadPacket>::ptr_type packet)
{
	PackStream stream_len(packet->value.len, packet->value.LEN_LEN);
	IntType(32) payload_len;
	stream_len >> payload_len;
	packet->value.unpacked_len = payload_len.get();
	packet->value.payload = new char[packet->value.unpacked_len + 1];

	boost::asio::async_read(*socket, boost::asio::buffer(packet->value.payload, packet->value.unpacked_len),
		[this, packet](boost::system::error_code ec, std::size_t length)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_payload (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_POOL << "PoolSocket::read_payload canceled";
				return;
			}

			final_read_message(packet);
			read();
		}
	);
}

void CoindSocket::final_read_message(SocketPacket<ReadPacket>::ptr_type packet)
{
	//checksum check
    auto checksum = coind::data::hash256(PackStream(packet->value.payload, packet->value.unpacked_len), true).GetChars();
    if (!c2pool::dev::compare_str(checksum.data(), packet->value.checksum, 4))
    {
		error(libp2p::BAD_PEER, (boost::format("[socket] Invalid hash for %1%, command %2%") % get_addr().to_string() % packet->value.command).str());
		return;
    }

	//Make raw message
	PackStream stream_RawMsg;

	std::string cmd(packet->value.command);
	PackStream stream_payload(packet->value.payload, packet->value.unpacked_len);

	stream_RawMsg << stream_payload;

	shared_ptr<RawMessage> raw_message = std::make_shared<RawMessage>(cmd);
	stream_RawMsg >> *raw_message;

    event_handle_message->happened(packet->value.command);
	//Protocol handle message
	msg_handler(raw_message);
}